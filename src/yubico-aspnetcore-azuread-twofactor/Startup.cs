using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using yubicoaspnetcoreazureadtwofactor.Helpers;

namespace yubicoaspnetcoreazureadtwofactor
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddJsonFile("config.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"config.{env.EnvironmentName}.json", optional: true);

            if (env.IsDevelopment())
            {
                // For more details on using the user secret store see http://go.microsoft.com/fwlink/?LinkID=532709
                builder.AddUserSecrets();
            }
            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add framework services.
            services.AddMvc();

            // Add functionality to inject IOptions<T>
            services.AddOptions();
            services.AddSession();

            services.AddAuthentication(sharedOptions =>
            {
                sharedOptions.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            });

            // Add our Config object so it can be injected
            services.Configure<YubiKeySettings>(Configuration.GetSection("YubiKey"));

            // *If* you need access to generic IConfiguration this is **required**
            services.TryAddSingleton<IConfigurationRoot>(Configuration);   // IConfigurationRoot
            services.TryAddSingleton<IConfiguration>(Configuration);   // IConfiguration explicitly
            // Hosting doesn't add IHttpContextAccessor by default
            services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();


            services.AddAuthorization(options =>
            { 
                options.AddPolicy("YubiKeyOTP", policy =>
                {
                    policy.Requirements.Add(new YubiKeyRequirement());
                });
            });

            services.AddSingleton<IAuthorizationHandler, YubiKeyHandler>(provider => new YubiKeyHandler(provider.GetRequiredService<IHttpContextAccessor>()));


        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseCookieAuthentication();

            app.UseOpenIdConnectAuthentication(new OpenIdConnectOptions()
            {
                ClientId = Configuration["Authentication:AzureAd:ClientId"],
                ClientSecret = Configuration["Authentication:AzureAd:ClientSecret"],
                Authority = "https://login.windows.net/common", //string.Format(Configuration["Authentication:AzureAd:AADInstance"], Configuration["Authentication:AzureAd:Tenant"]), // string.Format(Configuration["Authentication:AzureAd:AADInstance"], "Common"),
                CallbackPath = Configuration["Authentication:AzureAd:CallbackPath"],
                ResponseType = OpenIdConnectResponseType.IdToken,

                TokenValidationParameters = new TokenValidationParameters
                {
                    // Instead of using the default validation (validating against a single issuer value, as we do in line of business apps),
                    // we inject our own multitenant validation logic
                    ValidateIssuer = false,
                    

                    // If the app is meant to be accessed by entire organizations, add your issuer validation logic here.
                    //IssuerValidator = (issuer, securityToken, validationParameters) => {
                    //    if (myIssuerValidationLogic(issuer)) return issuer;
                    //}
                },
                Events = new OpenIdConnectEvents
                {
                    OnTicketReceived = (context) =>
                    {
                        // If your authentication logic is based on users then add your logic here
                        return Task.FromResult(0);
                    }
                    ,OnAuthenticationFailed = (context) =>
                    {
                        context.Response.Redirect("/Home/Error");
                        context.HandleResponse(); // Suppress the exception
                        return Task.FromResult(0);
                    }
                    // If your application needs to do authenticate single users, add your user validation below.
                    ,OnTokenValidated = (context) =>
                    {
                        //return myUserValidationLogic(context.Ticket.Principal);
                        return Task.FromResult(0);
                    }
                    ,OnRedirectToIdentityProvider = (context) =>
                    {

                        if (context.Request.Path != new PathString("/Account/TwoFactorSignIn"))
                        {
                            context.Properties.Items[".redirect"] = new PathString("/Account/TwoFactorSignIn");
                            context.Request.Path = new PathString("/Account/TwoFactorSignIn");
                        }

                        return Task.FromResult(0);
                    }
                }
            });

            app.UseSession();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "areaRoute",
                    template: "{area:exists}/{controller=Home}/{action=Index}/{id?}");

                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
