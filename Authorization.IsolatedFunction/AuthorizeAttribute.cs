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

namespace Sidub.Platform.Authorization.IsolatedFunction
{

    /// <summary>
    /// Specifies that the class or method requires authorization.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class AuthorizeAttribute : Attribute
    {

        /// <summary>
        /// Gets or sets the required scopes for authorization.
        /// </summary>
        public string[] Scopes { get; set; } = [];

        /// <summary>
        /// Gets or sets the required user roles for authorization.
        /// </summary>
        public string[] UserRoles { get; set; } = [];

        /// <summary>
        /// Gets or sets the required application roles for authorization.
        /// </summary>
        public string[] ApplicationRoles { get; set; } = [];

    }

}
