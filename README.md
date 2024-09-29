# Sidub Platform - Authorization - Isolated Function

This repository contains the Isolated Function authorization module for
the Sidub Platform. It provides the ability to control authorization
requirements for accessing isolated functions.

## Main Components
To leverage the authorization framework, it must be first registered
within the function. To do this, simply call the 
`AddSidubAuthorizationForIsolatedFunction` method on the 
`IFunctionsWorkerApplicationBuilder` instance.

```csharp
var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults((context, builder) =>
    {
        builder.AddSidubAuthorizationForIsolatedFunction();

    })
    .ConfigureServices((context, services) =>
    {

    })
    .Build();

host.Run();
```

Once the authorization framework is registered, you can use the `Authorize` 
attribute to control access to functions. Using the `AllowAnonymous` attribute
(Sidub.Platform.Authentication.IsolatedFunction) will allow access to the
function without requiring any specific authorization.

Additional documentation and functionality will be added.

## License
This project is dual-licensed under the AGPL v3 or a proprietary license. For
details, see [https://sidub.ca/licensing](https://sidub.ca/licensing) or the
LICENSE.txt file.