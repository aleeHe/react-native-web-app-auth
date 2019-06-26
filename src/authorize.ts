import { AuthorizationNotifier } from '@openid/appauth/built/authorization_request_handler';
import { RedirectRequestHandler } from '@openid/appauth/built/redirect_based_handler';
import { AuthorizationServiceConfiguration } from '@openid/appauth/built/authorization_service_configuration';
import { AuthorizationRequest } from '@openid/appauth/built/authorization_request';
import { BaseTokenRequestHandler } from '@openid/appauth/built/token_request_handler';
import { FetchRequestor } from '@openid/appauth/built/xhr';
import { TokenRequest, GRANT_TYPE_AUTHORIZATION_CODE } from '@openid/appauth/built/token_request';
import { StringMap, LocationLike } from '@openid/appauth/built/types';
import { LocalStorageBackend } from '@openid/appauth/built/storage';
import { BasicQueryStringUtils } from '@openid/appauth/built/query_string_utils';

export default ({
  issuer,
  redirectUrl,
  clientId,
  clientSecret,
  scopes,
  additionalParameters,
  serviceConfiguration,
  isRedirect
}) =>
  new Promise(async (resolve, reject) => {
    try {
      const requestor = new FetchRequestor();
      const authorizationHandler = new RedirectRequestHandler(new LocalStorageBackend(localStorage), new NoHashQueryStringUtils(), window.location);
      const notifier: AuthorizationNotifier = new AuthorizationNotifier();
      let configuration: AuthorizationServiceConfiguration;
      let extras: StringMap | undefined = additionalParameters;

      if (clientSecret) {
        extras['client_secret'] = clientSecret;
      }

      // put some default
      extras = {
        ...extras,
        prompt: 'consent',
        access_type: 'offline',
      };

      // fetch configuration if not provided
      if (!serviceConfiguration) {
        configuration = await AuthorizationServiceConfiguration.fetchFromIssuer(issuer, requestor);
      } else {
        configuration = new AuthorizationServiceConfiguration(serviceConfiguration);
      }

      authorizationHandler.setAuthorizationNotifier(notifier);

      notifier.setAuthorizationListener(async (request, response, error) => {
        console.log('Authorization request complete ', request, response, error);
        if (response) {
          let code = response.code;
          let tokenHandler = new BaseTokenRequestHandler(requestor);

          let _request: TokenRequest | null = null;

          if (code) {
            // use the code to make the token request.
            _request = new TokenRequest({
              client_id: clientId,
              redirect_uri: redirectUrl,
              grant_type: GRANT_TYPE_AUTHORIZATION_CODE,
              code: code,
              refresh_token: undefined,
              extras,
            });

            extras['code_verifier'] = request.internal['code_verifier'];

            let response = await tokenHandler.performTokenRequest(configuration, _request);
            resolve(response);
          }
        }
      });

      if (isRedirect) {
        if (await localStorage.getItem("appauth_current_authorization_request")) {
          try {
            await authorizationHandler.completeAuthorizationRequestIfPossible()
          } catch(err) {
            reject(err)
          } finally {
            return
          }
        }
        reject()
        return
      }


      // create a request
      let request = new AuthorizationRequest({
        client_id: clientId,
        redirect_uri: redirectUrl,
        scope: scopes.join(' '),
        response_type: AuthorizationRequest.RESPONSE_TYPE_CODE,
        state: undefined,
        extras,
      });

      // make the authorization request
      authorizationHandler.performAuthorizationRequest(configuration, request);
    } catch (err) {
      console.log(err);
      reject(err);
    }
  });


export class NoHashQueryStringUtils extends BasicQueryStringUtils {
  parse(input: LocationLike, useHash?: boolean): StringMap {
    return super.parse(input, false /* never use hash */);
  }
}