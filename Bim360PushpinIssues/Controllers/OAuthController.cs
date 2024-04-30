/////////////////////////////////////////////////////////////////////
// Copyright (c) Autodesk, Inc. All rights reserved
// Written by APS Partner Development
//
// Permission to use, copy, modify, and distribute this software in
// object code form for any purpose and without fee is hereby granted,
// provided that the above copyright notice appears in all copies and
// that both that copyright notice and the limited warranty and
// restricted rights notice below appear in all supporting
// documentation.
//
// AUTODESK PROVIDES THIS PROGRAM "AS IS" AND WITH ALL FAULTS.
// AUTODESK SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTY OF
// MERCHANTABILITY OR FITNESS FOR A PARTICULAR USE.  AUTODESK, INC.
// DOES NOT WARRANT THAT THE OPERATION OF THE PROGRAM WILL BE
// UNINTERRUPTED OR ERROR FREE.
/////////////////////////////////////////////////////////////////////

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Autodesk.Forge;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Http;
using System.Net;
using Autodesk.Authentication;
using Autodesk.Authentication.Model;
using Autodesk.SDKManager;
using System.Collections.Generic;
using System.IO;

namespace Bim360PushpinIssues.Controllers
{
    public class OAuthController : ControllerBase
    {

        AuthenticationClient authenticationClient = null!;
        string client_id = Credentials.GetAppSetting("APS_CLIENT_ID");
        string client_secret = Credentials.GetAppSetting("APS_CLIENT_SECRET");
        string redirect_uri = Credentials.GetAppSetting("APS_CALLBACK_URL");

        [HttpGet]
        [Route("api/aps/oauth/token")]
        public async Task<AccessToken> GetPublicTokenAsync()
        {
            Credentials credentials = await Credentials.FromSessionAsync(Request.Cookies, Response.Cookies);

            if (credentials == null)
            {
                base.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                return new AccessToken();
            }

            // return the public (viewables:read) access token
            return new AccessToken()
            {
                access_token = credentials.TokenPublic,
                expires_in = (int)credentials.ExpiresAt.Subtract(DateTime.Now).TotalSeconds
            };
        }

        /// <summary>
        /// Response for GetPublicToken
        /// </summary>
        public struct AccessToken
        {
            public string access_token { get; set; }
            public int expires_in { get; set; }
        }

        [HttpGet]
        [Route("api/aps/oauth/signout")]
        public IActionResult Singout()
        {
            // finish the session
            Credentials.Signout(base.Response.Cookies);
            return Redirect("/");
        }

        [HttpGet]
        [Route("api/aps/oauth/url")]
        public string GetOAuthURL()
        {
            // Instantiate SDK manager as below.  
            SDKManager sdkManager = SdkManagerBuilder
                  .Create() // Creates SDK Manager Builder itself.
                  .Build();

            // Instantiate AuthenticationClient using the created SDK manager
            authenticationClient = new AuthenticationClient(sdkManager);
            // prepare the sign in URL
           
            string oauthUrl = authenticationClient.Authorize(client_id, ResponseType.Code, redirect_uri, 
                new List<Scopes>() { Scopes.DataRead, Scopes.DataCreate, Scopes.DataWrite, Scopes.ViewablesRead, Scopes.AccountRead });

            return oauthUrl;
        }

        [HttpGet]
        [Route("api/aps/callback/oauth")] // see Web.Config APS_CALLBACK_URL variable
        public async Task<IActionResult> OAuthCallbackAsync(string code)
        {
            // create credentials from the oAuth CODE

           

            _ = await Credentials.CreateFromCodeAsync(code, Response.Cookies);


            return Redirect("/");
        }

        [HttpGet]
        [Route("api/aps/clientid")] // see Web.Config APS_CALLBACK_URL variable
        public dynamic GetClientID()
        {
            return new { id = Credentials.GetAppSetting("APS_CLIENT_ID") };
        }
    }

    /// <summary>
    /// Store data in session
    /// </summary>
    public class Credentials
    {


        private const string APS_COOKIE = "APSApp";


        private Credentials() { }
        public string TokenInternal { get; set; }
        public string TokenPublic { get; set; }
        public string RefreshToken { get; set; }
        public DateTime ExpiresAt { get; set; }

        public static AuthenticationClient authenticationClient = null;

        /// <summary>
        /// Perform the OAuth authorization via code
        /// </summary>
        /// <param name="code"></param>
        /// <returns></returns>
        public static async Task<Credentials> CreateFromCodeAsync( string code,IResponseCookies cookies)
        {
            // Instantiate SDK manager as below.  
            SDKManager sdkManager = SdkManagerBuilder
                  .Create() // Creates SDK Manager Builder itself.
                  .Build();

            // Instantiate AuthenticationClient using the created SDK manager
            authenticationClient = new AuthenticationClient(sdkManager);
            
            dynamic credentialInternal = await authenticationClient.GetThreeLeggedTokenAsync(GetAppSetting("APS_CLIENT_ID"), GetAppSetting("APS_CLIENT_SECRET"), code, GetAppSetting("APS_CALLBACK_URL"));

            dynamic credentialPublic = await authenticationClient.GetRefreshTokenAsync(GetAppSetting("APS_CLIENT_ID"), GetAppSetting("APS_CLIENT_SECRET"), credentialInternal.RefreshToken, new List<Scopes> { Scopes.ViewablesRead });

            Credentials credentials = new Credentials();
            credentials.TokenInternal = credentialInternal.AccessToken;
            credentials.TokenPublic = credentialPublic.AccessToken;
            credentials.RefreshToken = credentialPublic._RefreshToken;
            credentials.ExpiresAt = DateTime.Now.AddSeconds(credentialInternal.ExpiresIn);

            cookies.Append(APS_COOKIE, JsonConvert.SerializeObject(credentials));

            return credentials;
        }

        /// <summary>
        /// Restore the credentials from the session object, refresh if needed
        /// </summary>
        /// <returns></returns>
        public static async Task<Credentials> FromSessionAsync(IRequestCookieCollection requestCookie, IResponseCookies responseCookie)
        {
            if (requestCookie == null || !requestCookie.ContainsKey(APS_COOKIE)) return null;

            Credentials credentials = JsonConvert.DeserializeObject<Credentials>(requestCookie[APS_COOKIE]);
            if (credentials.ExpiresAt < DateTime.Now)
            {
                await credentials.RefreshAsync();
                responseCookie.Delete(APS_COOKIE);
                responseCookie.Append(APS_COOKIE, JsonConvert.SerializeObject(credentials));
            }

            return credentials;
        }

        public static void Signout(IResponseCookies cookies)
        {
            cookies.Delete(APS_COOKIE);
        }

        /// <summary>
        /// Refresh the credentials (internal & external)
        /// </summary>
        /// <returns></returns>
        private async Task RefreshAsync()
        {
           
            dynamic credentialInternal =await  authenticationClient.GetRefreshTokenAsync(GetAppSetting("APS_CLIENT_ID"), GetAppSetting("APS_CLIENT_SECRET"), 
                RefreshToken, new List<Scopes> { Scopes.DataRead, Scopes.DataCreate, Scopes.DataWrite, Scopes.AccountRead });


            dynamic credentialPublic = await authenticationClient.GetRefreshTokenAsync(GetAppSetting("APS_CLIENT_ID"), GetAppSetting("APS_CLIENT_SECRET"), 
                credentialInternal.RefreshToken, new List<Scopes> { Scopes.ViewablesRead });

            TokenInternal = credentialInternal.AccessToken;
            TokenPublic = credentialPublic.AccessToken;
            RefreshToken = credentialPublic._RefreshToken;
            ExpiresAt = DateTime.Now.AddSeconds(credentialInternal.ExpiresIn);
        }

        /// <summary>
        /// Reads appsettings from web.config
        /// </summary>
        public static string GetAppSetting(string settingKey)
        {
            return Environment.GetEnvironmentVariable(settingKey);
        }
     
    }
}
