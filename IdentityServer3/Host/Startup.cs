using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens;
using Host;
using Host.Configuration;
using Host.Manager;
using IdentityManager.Configuration;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.MicrosoftAccount;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Thinktecture.IdentityServer.Core.Configuration;
using Microsoft.Owin.Security.WsFederation;
using System.Threading.Tasks;
using System.Globalization;
[assembly: OwinStartup(typeof(Startup))]

namespace Host
{
    public class Startup
    {
        public void Configuration(IAppBuilder appBuilder)
        {
            var connectionString = ConfigurationManager.AppSettings["Connection"];

            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            appBuilder.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies"
            });

            appBuilder.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            appBuilder.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                AuthenticationType = "oidc",
                Authority = ConfigurationManager.AppSettings["IdentityServer"],
                ClientId = "idmgr_client",
                RedirectUri = ConfigurationManager.AppSettings["IdentityManager"],
                ResponseType = "id_token",
                UseTokenLifetime = false,
                Scope = "openid idmgr",
                SignInAsAuthenticationType = "Cookies"
            });


            // Identity Manager
            appBuilder.Map("/admin", adminApp =>
            {
                var factory = new IdentityManagerServiceFactory();
                factory.Configure(connectionString);

                var options = new IdentityManagerOptions
                {
                    Factory = factory
                };

                if (Convert.ToBoolean(ConfigurationManager.AppSettings["SecurityEnabled"]))
                {
                    options.SecurityConfiguration = new HostSecurityConfiguration
                    {
                        HostAuthenticationType = "Cookies",
                        AdditionalSignOutType = "oidc"
                    };
                }

                adminApp.UseIdentityManager(options);
            });

            // Identity Server
            var idFactory = new IdentityServerServiceFactory();
            idFactory.Configure(connectionString);

            var idOptions = new IdentityServerOptions
            {
                SigningCertificate = Certificate.Load(),
                Factory = idFactory,
                CorsPolicy = CorsPolicy.AllowAll,
                AuthenticationOptions = new AuthenticationOptions
                {
                    IdentityProviders = ConfigureIdentityProviders
                }
            };

            appBuilder.UseIdentityServer(idOptions);
        }

        private void ConfigureIdentityProviders(IAppBuilder app, string signInAsType)
        {
            app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions
            {
                AuthenticationType = "Google",
                Caption = ConfigurationManager.AppSettings["googlecaption"],
                SignInAsAuthenticationType = signInAsType,

                ClientId = ConfigurationManager.AppSettings["googleclientid"],
                ClientSecret = ConfigurationManager.AppSettings["googleclientsecret"]
            });

            app.UseMicrosoftAccountAuthentication(new MicrosoftAccountAuthenticationOptions
            {
                AuthenticationType = "Microsoft",
                Caption = ConfigurationManager.AppSettings["mscaption"],
                SignInAsAuthenticationType = signInAsType,

                ClientId = ConfigurationManager.AppSettings["msclientid"],
                ClientSecret = ConfigurationManager.AppSettings["msclientsecret"]
            });


            //authentication in azure ad using ws-federation.
            //current configuration is using my machine's credentials, if any change is done in the azure ad then the end-points for the ws-federation metatdata is
            //needed to be updated in the config file.
            var azureAdWithWSFed = new WsFederationAuthenticationOptions
            {
                AuthenticationType = "AzureAdFed",
                Caption = ConfigurationManager.AppSettings["caption"],
                SignInAsAuthenticationType = signInAsType,
                MetadataAddress = ConfigurationManager.AppSettings["fedmetadata"],
                Wtrealm = ConfigurationManager.AppSettings["wtrealm"]
            };
            app.UseWsFederationAuthentication(azureAdWithWSFed);
        }
    }
}
