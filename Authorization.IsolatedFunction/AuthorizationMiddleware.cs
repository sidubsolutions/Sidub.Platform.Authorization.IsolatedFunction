/*
 * Sidub Platform - Authorization - Isolated Function
 * Copyright (C) 2024 Sidub Inc.
 * All rights reserved.
 *
 * This file is part of Sidub Platform - Authorization - Isolated Function (the "Product").
 *
 * The Product is dual-licensed under:
 * 1. The GNU Affero General Public License version 3 (AGPLv3)
 * 2. Sidub Inc.'s Proprietary Software License Agreement (PSLA)
 *
 * You may choose to use, redistribute, and/or modify the Product under
 * the terms of either license.
 *
 * The Product is provided "AS IS" and "AS AVAILABLE," without any
 * warranties or conditions of any kind, either express or implied, including
 * but not limited to implied warranties or conditions of merchantability and
 * fitness for a particular purpose. See the applicable license for more
 * details.
 *
 * See the LICENSE.txt file for detailed license terms and conditions or
 * visit https://sidub.ca/licensing for a copy of the license texts.
 */

#region Imports

using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using Sidub.Platform.Authentication;
using Sidub.Platform.Authentication.IsolatedFunction;
using Sidub.Platform.Authentication.IsolatedFunction.AuthenticationData;
using System.Net;
using System.Reflection;
using System.Security.Claims;

#endregion

namespace Sidub.Platform.Authorization.IsolatedFunction
{

    /// <summary>
    /// Middleware for authorization in Azure Functions.
    /// </summary>
    public class AuthorizationMiddleware : IFunctionsWorkerMiddleware
    {

        #region Member variables

        private const string ScopeClaimType = "http://schemas.microsoft.com/identity/claims/scope";

        #endregion

        #region Public methods

        /// <summary>
        /// Invokes the authorization middleware.
        /// </summary>
        /// <param name="context">The function context.</param>
        /// <param name="next">The next middleware delegate.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task Invoke(
            FunctionContext context,
            FunctionExecutionDelegate next)
        {
            var authorizationData = context.Features.Get<IAuthenticationData>()
                ?? throw new Exception("Authentication data (IAuthenticationData) could not be found. Please ensure the authentication middleware is registered and done so before authorization middleware.");

            if (!AuthorizePrincipal(context, authorizationData))
            {
                await context.SetHttpResponseStatusCode(HttpStatusCode.Forbidden);
                return;
            }

            ClaimsPrincipal.ClaimsPrincipalSelector = () => authorizationData.Principal;

            await next(context);
        }

        #endregion

        #region Private methods

        /// <summary>
        /// Authorizes the principal based on the authentication data.
        /// </summary>
        /// <param name="context">The function context.</param>
        /// <param name="authenticationData">The authentication data.</param>
        /// <returns><c>true</c> if the principal is authorized; otherwise, <c>false</c>.</returns>
        private static bool AuthorizePrincipal(FunctionContext context, IAuthenticationData authenticationData)
        {
            var principal = authenticationData.Principal;

            if (DoesAuthorizationExistOnTarget(context))
            {
                if (principal is null)
                    throw new Exception("Security principal was not found. Ensure the request was sent with a properly formed, authenticated request token.");

                if (principal.HasClaim(c => c.Type == ScopeClaimType))
                {
                    // request made with delegated permissions, check appRoles and user roles...
                    return AuthorizeDelegatedPermissions(context, principal);
                }

                // request made with application permissions, check app roles...
                return AuthorizeApplicationPermissions(context, principal);
            }

            return true;
        }

        /// <summary>
        /// Checks if authorization exists on the target method.
        /// </summary>
        /// <param name="context">The function context.</param>
        /// <returns><c>true</c> if authorization exists; otherwise, <c>false</c>.</returns>
        private static bool DoesAuthorizationExistOnTarget(FunctionContext context)
        {
            var method = context.GetTargetFunctionMethod();

            // first check for allow anonymous access...
            if (method.GetCustomAttributes<AllowAnonymousAttribute>().Any() || (method.DeclaringType?.GetCustomAttributes<AllowAnonymousAttribute>().Any() ?? false))
                return false;

            return method.GetCustomAttributes<AuthorizeAttribute>().Any() || (method.DeclaringType?.GetCustomAttributes<AuthorizeAttribute>().Any() ?? false);
        }

        /// <summary>
        /// Authorizes the principal based on delegated permissions.
        /// </summary>
        /// <param name="context">The function context.</param>
        /// <param name="principal">The claims principal.</param>
        /// <returns><c>true</c> if the principal is authorized; otherwise, <c>false</c>.</returns>
        private static bool AuthorizeDelegatedPermissions(FunctionContext context, ClaimsPrincipal principal)
        {
            var targetMethod = context.GetTargetFunctionMethod();

            var (acceptedScopes, acceptedUserRoles) = GetAcceptedScopesAndUserRoles(targetMethod);
            var userRoles = principal.FindAll(ClaimTypes.Role);

            var userHasAcceptedRole = userRoles.Any(ur => acceptedUserRoles.Contains(ur.Value));
            var callerScopesClaim = principal.FindFirst(ScopeClaimType);
            var callerHasAcceptedScope = false;

            if (callerScopesClaim != null)
            {
                var callerScopes = callerScopesClaim.Value.Split(" ".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
                callerHasAcceptedScope = callerScopes.Intersect(acceptedScopes).Any();
            }

            return acceptedScopes.Any() ? (userHasAcceptedRole && callerHasAcceptedScope) : userHasAcceptedRole;
        }

        /// <summary>
        /// Authorizes the principal based on application permissions.
        /// </summary>
        /// <param name="context">The function context.</param>
        /// <param name="principal">The claims principal.</param>
        /// <returns><c>true</c> if the principal is authorized; otherwise, <c>false</c>.</returns>
        private static bool AuthorizeApplicationPermissions(FunctionContext context, ClaimsPrincipal principal)
        {
            var targetMethod = context.GetTargetFunctionMethod();

            var acceptedAppRoles = GetAcceptedAppRoles(targetMethod);
            var appRoles = principal.FindAll(ClaimTypes.Role);

            var appHasAcceptedRole = appRoles.Any(ur => acceptedAppRoles.Contains(ur.Value));

            return appHasAcceptedRole;
        }

        /// <summary>
        /// Gets the accepted scopes and user roles for the target method.
        /// </summary>
        /// <param name="targetMethod">The target method.</param>
        /// <returns>A tuple containing the accepted scopes and user roles.</returns>
        private static (IEnumerable<string> scopes, IEnumerable<string> userRoles) GetAcceptedScopesAndUserRoles(MethodInfo targetMethod)
        {
            var scopes = Enumerable.Empty<string>();
            var userRoles = Enumerable.Empty<string>();
            var methodAuthorizations = targetMethod.GetCustomAttributes<AuthorizeAttribute>(true);

            if (methodAuthorizations.Any())
            {
                // target method has authorizations declared...
                scopes = methodAuthorizations.SelectMany(auth => auth.Scopes);
                userRoles = methodAuthorizations.SelectMany(auth => auth.UserRoles);

                return (scopes, userRoles);
            }

            var classAuthorizations = targetMethod.DeclaringType?.GetCustomAttributes<AuthorizeAttribute>(true)
                ?? Enumerable.Empty<AuthorizeAttribute>();

            if (classAuthorizations.Any())
            {
                // target method does not have authorizations, but the declaring class does...
                scopes = classAuthorizations.SelectMany(auth => auth.Scopes);
                userRoles = classAuthorizations.SelectMany(auth => auth.UserRoles);

                return (scopes, userRoles);
            }

            return (scopes, userRoles);
        }

        /// <summary>
        /// Gets the accepted application roles for the target method.
        /// </summary>
        /// <param name="targetMethod">The target method.</param>
        /// <returns>The accepted application roles.</returns>
        private static IEnumerable<string> GetAcceptedAppRoles(MethodInfo targetMethod)
        {
            var appRoles = Enumerable.Empty<string>();
            var methodAuthorizations = targetMethod.GetCustomAttributes<AuthorizeAttribute>(true);

            if (methodAuthorizations.Any())
            {
                // target method has authorizations declared...
                appRoles = methodAuthorizations.SelectMany(auth => auth.ApplicationRoles);

                return appRoles;
            }

            var classAuthorizations = targetMethod.DeclaringType?.GetCustomAttributes<AuthorizeAttribute>(true)
                ?? Enumerable.Empty<AuthorizeAttribute>();

            if (classAuthorizations.Any())
            {
                // target method does not have authorizations, but the declaring class does...
                appRoles = classAuthorizations.SelectMany(auth => auth.ApplicationRoles);

                return appRoles;
            }

            return appRoles;
        }

        #endregion

    }

}
