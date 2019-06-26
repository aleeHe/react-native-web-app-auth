var _interopRequireDefault=require("@babel/runtime/helpers/interopRequireDefault");Object.defineProperty(exports,"__esModule",{value:true});exports.NoHashQueryStringUtils=exports.default=void 0;var _classCallCheck2=_interopRequireDefault(require("@babel/runtime/helpers/classCallCheck"));var _createClass2=_interopRequireDefault(require("@babel/runtime/helpers/createClass"));var _possibleConstructorReturn2=_interopRequireDefault(require("@babel/runtime/helpers/possibleConstructorReturn"));var _getPrototypeOf2=_interopRequireDefault(require("@babel/runtime/helpers/getPrototypeOf"));var _get2=_interopRequireDefault(require("@babel/runtime/helpers/get"));var _inherits2=_interopRequireDefault(require("@babel/runtime/helpers/inherits"));var _regenerator=_interopRequireDefault(require("@babel/runtime/regenerator"));var _objectSpread2=_interopRequireDefault(require("@babel/runtime/helpers/objectSpread"));var _authorization_request_handler=require("@openid/appauth/built/authorization_request_handler");var _redirect_based_handler=require("@openid/appauth/built/redirect_based_handler");var _authorization_service_configuration=require("@openid/appauth/built/authorization_service_configuration");var _authorization_request=require("@openid/appauth/built/authorization_request");var _token_request_handler=require("@openid/appauth/built/token_request_handler");var _xhr=require("@openid/appauth/built/xhr");var _token_request=require("@openid/appauth/built/token_request");var _storage=require("@openid/appauth/built/storage");var _query_string_utils=require("@openid/appauth/built/query_string_utils");var _default=function _default(_ref){var issuer=_ref.issuer,redirectUrl=_ref.redirectUrl,clientId=_ref.clientId,clientSecret=_ref.clientSecret,scopes=_ref.scopes,additionalParameters=_ref.additionalParameters,serviceConfiguration=_ref.serviceConfiguration,isRedirect=_ref.isRedirect;return new Promise(function _callee2(resolve,reject){var requestor,authorizationHandler,notifier,configuration,extras,request;return _regenerator.default.async(function _callee2$(_context2){while(1){switch(_context2.prev=_context2.next){case 0:_context2.prev=0;requestor=new _xhr.FetchRequestor;authorizationHandler=new _redirect_based_handler.RedirectRequestHandler(new _storage.LocalStorageBackend(localStorage),new NoHashQueryStringUtils(),window.location);notifier=new _authorization_request_handler.AuthorizationNotifier;extras=additionalParameters;if(clientSecret){extras["client_secret"]=clientSecret}extras=(0,_objectSpread2.default)({},extras,{prompt:"consent",access_type:"offline"});if(serviceConfiguration){_context2.next=13;break}_context2.next=10;return _regenerator.default.awrap(_authorization_service_configuration.AuthorizationServiceConfiguration.fetchFromIssuer(issuer,requestor));case 10:configuration=_context2.sent;_context2.next=14;break;case 13:configuration=new _authorization_service_configuration.AuthorizationServiceConfiguration(serviceConfiguration);case 14:authorizationHandler.setAuthorizationNotifier(notifier);notifier.setAuthorizationListener(function _callee(request,response,error){var code,tokenHandler,_request,_response;return _regenerator.default.async(function _callee$(_context){while(1){switch(_context.prev=_context.next){case 0:console.log("Authorization request complete ",request,response,error);if(!response){_context.next=12;break}code=response.code;tokenHandler=new _token_request_handler.BaseTokenRequestHandler(requestor);_request=null;if(!code){_context.next=12;break}_request=new _token_request.TokenRequest({client_id:clientId,redirect_uri:redirectUrl,grant_type:_token_request.GRANT_TYPE_AUTHORIZATION_CODE,code:code,refresh_token:undefined,extras:extras});extras["code_verifier"]=request.internal["code_verifier"];_context.next=10;return _regenerator.default.awrap(tokenHandler.performTokenRequest(configuration,_request));case 10:_response=_context.sent;resolve(_response);case 12:case"end":return _context.stop();}}})});if(!isRedirect){_context2.next=33;break}_context2.next=19;return _regenerator.default.awrap(localStorage.getItem("appauth_current_authorization_request"));case 19:if(!_context2.sent){_context2.next=31;break}_context2.prev=20;_context2.next=23;return _regenerator.default.awrap(authorizationHandler.completeAuthorizationRequestIfPossible());case 23:_context2.next=28;break;case 25:_context2.prev=25;_context2.t0=_context2["catch"](20);reject(_context2.t0);case 28:_context2.prev=28;return _context2.abrupt("return");case 31:reject();return _context2.abrupt("return");case 33:request=new _authorization_request.AuthorizationRequest({client_id:clientId,redirect_uri:redirectUrl,scope:scopes.join(" "),response_type:_authorization_request.AuthorizationRequest.RESPONSE_TYPE_CODE,state:undefined,extras:extras});authorizationHandler.performAuthorizationRequest(configuration,request);_context2.next=41;break;case 37:_context2.prev=37;_context2.t1=_context2["catch"](0);console.log(_context2.t1);reject(_context2.t1);case 41:case"end":return _context2.stop();}}},null,null,[[0,37],[20,25,28,31]])})};exports.default=_default;var NoHashQueryStringUtils=function(_BasicQueryStringUtil){(0,_inherits2.default)(NoHashQueryStringUtils,_BasicQueryStringUtil);function NoHashQueryStringUtils(){(0,_classCallCheck2.default)(this,NoHashQueryStringUtils);return(0,_possibleConstructorReturn2.default)(this,(0,_getPrototypeOf2.default)(NoHashQueryStringUtils).apply(this,arguments))}(0,_createClass2.default)(NoHashQueryStringUtils,[{key:"parse",value:function parse(input,useHash){return(0,_get2.default)((0,_getPrototypeOf2.default)(NoHashQueryStringUtils.prototype),"parse",this).call(this,input,false)}}]);return NoHashQueryStringUtils}(_query_string_utils.BasicQueryStringUtils);exports.NoHashQueryStringUtils=NoHashQueryStringUtils;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9hdXRob3JpemUudHMiXSwibmFtZXMiOlsiaXNzdWVyIiwicmVkaXJlY3RVcmwiLCJjbGllbnRJZCIsImNsaWVudFNlY3JldCIsInNjb3BlcyIsImFkZGl0aW9uYWxQYXJhbWV0ZXJzIiwic2VydmljZUNvbmZpZ3VyYXRpb24iLCJpc1JlZGlyZWN0IiwiUHJvbWlzZSIsInJlc29sdmUiLCJyZWplY3QiLCJyZXF1ZXN0b3IiLCJGZXRjaFJlcXVlc3RvciIsImF1dGhvcml6YXRpb25IYW5kbGVyIiwiUmVkaXJlY3RSZXF1ZXN0SGFuZGxlciIsIkxvY2FsU3RvcmFnZUJhY2tlbmQiLCJsb2NhbFN0b3JhZ2UiLCJOb0hhc2hRdWVyeVN0cmluZ1V0aWxzIiwid2luZG93IiwibG9jYXRpb24iLCJub3RpZmllciIsIkF1dGhvcml6YXRpb25Ob3RpZmllciIsImV4dHJhcyIsInByb21wdCIsImFjY2Vzc190eXBlIiwiQXV0aG9yaXphdGlvblNlcnZpY2VDb25maWd1cmF0aW9uIiwiZmV0Y2hGcm9tSXNzdWVyIiwiY29uZmlndXJhdGlvbiIsInNldEF1dGhvcml6YXRpb25Ob3RpZmllciIsInNldEF1dGhvcml6YXRpb25MaXN0ZW5lciIsInJlcXVlc3QiLCJyZXNwb25zZSIsImVycm9yIiwiY29uc29sZSIsImxvZyIsImNvZGUiLCJ0b2tlbkhhbmRsZXIiLCJCYXNlVG9rZW5SZXF1ZXN0SGFuZGxlciIsIl9yZXF1ZXN0IiwiVG9rZW5SZXF1ZXN0IiwiY2xpZW50X2lkIiwicmVkaXJlY3RfdXJpIiwiZ3JhbnRfdHlwZSIsIkdSQU5UX1RZUEVfQVVUSE9SSVpBVElPTl9DT0RFIiwicmVmcmVzaF90b2tlbiIsInVuZGVmaW5lZCIsImludGVybmFsIiwicGVyZm9ybVRva2VuUmVxdWVzdCIsImdldEl0ZW0iLCJjb21wbGV0ZUF1dGhvcml6YXRpb25SZXF1ZXN0SWZQb3NzaWJsZSIsIkF1dGhvcml6YXRpb25SZXF1ZXN0Iiwic2NvcGUiLCJqb2luIiwicmVzcG9uc2VfdHlwZSIsIlJFU1BPTlNFX1RZUEVfQ09ERSIsInN0YXRlIiwicGVyZm9ybUF1dGhvcml6YXRpb25SZXF1ZXN0IiwiaW5wdXQiLCJ1c2VIYXNoIiwiQmFzaWNRdWVyeVN0cmluZ1V0aWxzIl0sIm1hcHBpbmdzIjoiNjRCQUFBLGtHQUNBLG9GQUNBLDhHQUNBLGtGQUNBLGtGQUNBLDhDQUNBLGtFQUVBLHNEQUNBLDRFLGFBRWUsMkJBQ2JBLENBQUFBLE1BRGEsTUFDYkEsTUFEYSxDQUViQyxXQUZhLE1BRWJBLFdBRmEsQ0FHYkMsUUFIYSxNQUdiQSxRQUhhLENBSWJDLFlBSmEsTUFJYkEsWUFKYSxDQUtiQyxNQUxhLE1BS2JBLE1BTGEsQ0FNYkMsb0JBTmEsTUFNYkEsb0JBTmEsQ0FPYkMsb0JBUGEsTUFPYkEsb0JBUGEsQ0FRYkMsVUFSYSxNQVFiQSxVQVJhLE9BVWIsSUFBSUMsQ0FBQUEsT0FBSixDQUFZLGtCQUFPQyxPQUFQLENBQWdCQyxNQUFoQixrTkFFRkMsU0FGRSxDQUVVLEdBQUlDLG9CQUZkLENBR0ZDLG9CQUhFLENBR3FCLEdBQUlDLCtDQUFKLENBQTJCLEdBQUlDLDZCQUFKLENBQXdCQyxZQUF4QixDQUEzQixDQUFrRSxHQUFJQyxDQUFBQSxzQkFBSixFQUFsRSxDQUFnR0MsTUFBTSxDQUFDQyxRQUF2RyxDQUhyQixDQUlGQyxRQUpFLENBSWdDLEdBQUlDLHFEQUpwQyxDQU1KQyxNQU5JLENBTTRCakIsb0JBTjVCLENBUVIsR0FBSUYsWUFBSixDQUFrQixDQUNoQm1CLE1BQU0sQ0FBQyxlQUFELENBQU4sQ0FBMEJuQixZQUMzQixDQUdEbUIsTUFBTSwrQkFDREEsTUFEQyxFQUVKQyxNQUFNLENBQUUsU0FGSixDQUdKQyxXQUFXLENBQUUsU0FIVCxFQUFOLENBYlEsR0FvQkhsQixvQkFwQkcsOEVBcUJnQm1CLHVFQUFrQ0MsZUFBbEMsQ0FBa0QxQixNQUFsRCxDQUEwRFcsU0FBMUQsQ0FyQmhCLFVBcUJOZ0IsYUFyQk0sZ0RBdUJOQSxhQUFhLENBQUcsR0FBSUYsdUVBQUosQ0FBc0NuQixvQkFBdEMsQ0FBaEIsQ0F2Qk0sUUEwQlJPLG9CQUFvQixDQUFDZSx3QkFBckIsQ0FBOENSLFFBQTlDLEVBRUFBLFFBQVEsQ0FBQ1Msd0JBQVQsQ0FBa0MsaUJBQU9DLE9BQVAsQ0FBZ0JDLFFBQWhCLENBQTBCQyxLQUExQiw2SkFDaENDLE9BQU8sQ0FBQ0MsR0FBUixDQUFZLGlDQUFaLENBQStDSixPQUEvQyxDQUF3REMsUUFBeEQsQ0FBa0VDLEtBQWxFLEVBRGdDLElBRTVCRCxRQUY0Qix5QkFHMUJJLElBSDBCLENBR25CSixRQUFRLENBQUNJLElBSFUsQ0FJMUJDLFlBSjBCLENBSVgsR0FBSUMsK0NBQUosQ0FBNEIxQixTQUE1QixDQUpXLENBTTFCMkIsUUFOMEIsQ0FNTSxJQU5OLEtBUTFCSCxJQVIwQix5QkFVNUJHLFFBQVEsQ0FBRyxHQUFJQyw0QkFBSixDQUFpQixDQUMxQkMsU0FBUyxDQUFFdEMsUUFEZSxDQUUxQnVDLFlBQVksQ0FBRXhDLFdBRlksQ0FHMUJ5QyxVQUFVLENBQUVDLDRDQUhjLENBSTFCUixJQUFJLENBQUVBLElBSm9CLENBSzFCUyxhQUFhLENBQUVDLFNBTFcsQ0FNMUJ2QixNQUFNLENBQU5BLE1BTjBCLENBQWpCLENBQVgsQ0FTQUEsTUFBTSxDQUFDLGVBQUQsQ0FBTixDQUEwQlEsT0FBTyxDQUFDZ0IsUUFBUixDQUFpQixlQUFqQixDQUExQixDQW5CNEIsbURBcUJQVixZQUFZLENBQUNXLG1CQUFiLENBQWlDcEIsYUFBakMsQ0FBZ0RXLFFBQWhELENBckJPLFVBcUJ4QlAsU0FyQndCLGVBc0I1QnRCLE9BQU8sQ0FBQ3NCLFNBQUQsQ0FBUCxDQXRCNEIsOENBQWxDLEVBNUJRLElBdURKeEIsVUF2REksOEVBd0RJUyxZQUFZLENBQUNnQyxPQUFiLENBQXFCLHVDQUFyQixDQXhESiw0SEEwREluQyxvQkFBb0IsQ0FBQ29DLHNDQUFyQixFQTFESixnR0E0REZ2QyxNQUFNLGNBQU4sQ0E1REUsb0VBaUVOQSxNQUFNLEdBakVBLDBDQXVFSm9CLE9BdkVJLENBdUVNLEdBQUlvQiw0Q0FBSixDQUF5QixDQUNyQ1YsU0FBUyxDQUFFdEMsUUFEMEIsQ0FFckN1QyxZQUFZLENBQUV4QyxXQUZ1QixDQUdyQ2tELEtBQUssQ0FBRS9DLE1BQU0sQ0FBQ2dELElBQVAsQ0FBWSxHQUFaLENBSDhCLENBSXJDQyxhQUFhLENBQUVILDRDQUFxQkksa0JBSkMsQ0FLckNDLEtBQUssQ0FBRVYsU0FMOEIsQ0FNckN2QixNQUFNLENBQU5BLE1BTnFDLENBQXpCLENBdkVOLENBaUZSVCxvQkFBb0IsQ0FBQzJDLDJCQUFyQixDQUFpRDdCLGFBQWpELENBQWdFRyxPQUFoRSxFQWpGUSxxRkFtRlJHLE9BQU8sQ0FBQ0MsR0FBUixlQUNBeEIsTUFBTSxjQUFOLENBcEZRLGdGQUFaLENBVmEsQyw2QkFtR0ZPLENBQUFBLHNCLHFaQUNMd0MsSyxDQUFxQkMsTyxDQUE4QixDQUN2RCwrR0FBbUJELEtBQW5CLENBQTBCLEtBQTFCLENBQ0QsQyxtQ0FIeUNFLHlDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQXV0aG9yaXphdGlvbk5vdGlmaWVyIH0gZnJvbSAnQG9wZW5pZC9hcHBhdXRoL2J1aWx0L2F1dGhvcml6YXRpb25fcmVxdWVzdF9oYW5kbGVyJztcbmltcG9ydCB7IFJlZGlyZWN0UmVxdWVzdEhhbmRsZXIgfSBmcm9tICdAb3BlbmlkL2FwcGF1dGgvYnVpbHQvcmVkaXJlY3RfYmFzZWRfaGFuZGxlcic7XG5pbXBvcnQgeyBBdXRob3JpemF0aW9uU2VydmljZUNvbmZpZ3VyYXRpb24gfSBmcm9tICdAb3BlbmlkL2FwcGF1dGgvYnVpbHQvYXV0aG9yaXphdGlvbl9zZXJ2aWNlX2NvbmZpZ3VyYXRpb24nO1xuaW1wb3J0IHsgQXV0aG9yaXphdGlvblJlcXVlc3QgfSBmcm9tICdAb3BlbmlkL2FwcGF1dGgvYnVpbHQvYXV0aG9yaXphdGlvbl9yZXF1ZXN0JztcbmltcG9ydCB7IEJhc2VUb2tlblJlcXVlc3RIYW5kbGVyIH0gZnJvbSAnQG9wZW5pZC9hcHBhdXRoL2J1aWx0L3Rva2VuX3JlcXVlc3RfaGFuZGxlcic7XG5pbXBvcnQgeyBGZXRjaFJlcXVlc3RvciB9IGZyb20gJ0BvcGVuaWQvYXBwYXV0aC9idWlsdC94aHInO1xuaW1wb3J0IHsgVG9rZW5SZXF1ZXN0LCBHUkFOVF9UWVBFX0FVVEhPUklaQVRJT05fQ09ERSB9IGZyb20gJ0BvcGVuaWQvYXBwYXV0aC9idWlsdC90b2tlbl9yZXF1ZXN0JztcbmltcG9ydCB7IFN0cmluZ01hcCwgTG9jYXRpb25MaWtlIH0gZnJvbSAnQG9wZW5pZC9hcHBhdXRoL2J1aWx0L3R5cGVzJztcbmltcG9ydCB7IExvY2FsU3RvcmFnZUJhY2tlbmQgfSBmcm9tICdAb3BlbmlkL2FwcGF1dGgvYnVpbHQvc3RvcmFnZSc7XG5pbXBvcnQgeyBCYXNpY1F1ZXJ5U3RyaW5nVXRpbHMgfSBmcm9tICdAb3BlbmlkL2FwcGF1dGgvYnVpbHQvcXVlcnlfc3RyaW5nX3V0aWxzJztcblxuZXhwb3J0IGRlZmF1bHQgKHtcbiAgaXNzdWVyLFxuICByZWRpcmVjdFVybCxcbiAgY2xpZW50SWQsXG4gIGNsaWVudFNlY3JldCxcbiAgc2NvcGVzLFxuICBhZGRpdGlvbmFsUGFyYW1ldGVycyxcbiAgc2VydmljZUNvbmZpZ3VyYXRpb24sXG4gIGlzUmVkaXJlY3Rcbn0pID0+XG4gIG5ldyBQcm9taXNlKGFzeW5jIChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgcmVxdWVzdG9yID0gbmV3IEZldGNoUmVxdWVzdG9yKCk7XG4gICAgICBjb25zdCBhdXRob3JpemF0aW9uSGFuZGxlciA9IG5ldyBSZWRpcmVjdFJlcXVlc3RIYW5kbGVyKG5ldyBMb2NhbFN0b3JhZ2VCYWNrZW5kKGxvY2FsU3RvcmFnZSksIG5ldyBOb0hhc2hRdWVyeVN0cmluZ1V0aWxzKCksIHdpbmRvdy5sb2NhdGlvbik7XG4gICAgICBjb25zdCBub3RpZmllcjogQXV0aG9yaXphdGlvbk5vdGlmaWVyID0gbmV3IEF1dGhvcml6YXRpb25Ob3RpZmllcigpO1xuICAgICAgbGV0IGNvbmZpZ3VyYXRpb246IEF1dGhvcml6YXRpb25TZXJ2aWNlQ29uZmlndXJhdGlvbjtcbiAgICAgIGxldCBleHRyYXM6IFN0cmluZ01hcCB8IHVuZGVmaW5lZCA9IGFkZGl0aW9uYWxQYXJhbWV0ZXJzO1xuXG4gICAgICBpZiAoY2xpZW50U2VjcmV0KSB7XG4gICAgICAgIGV4dHJhc1snY2xpZW50X3NlY3JldCddID0gY2xpZW50U2VjcmV0O1xuICAgICAgfVxuXG4gICAgICAvLyBwdXQgc29tZSBkZWZhdWx0XG4gICAgICBleHRyYXMgPSB7XG4gICAgICAgIC4uLmV4dHJhcyxcbiAgICAgICAgcHJvbXB0OiAnY29uc2VudCcsXG4gICAgICAgIGFjY2Vzc190eXBlOiAnb2ZmbGluZScsXG4gICAgICB9O1xuXG4gICAgICAvLyBmZXRjaCBjb25maWd1cmF0aW9uIGlmIG5vdCBwcm92aWRlZFxuICAgICAgaWYgKCFzZXJ2aWNlQ29uZmlndXJhdGlvbikge1xuICAgICAgICBjb25maWd1cmF0aW9uID0gYXdhaXQgQXV0aG9yaXphdGlvblNlcnZpY2VDb25maWd1cmF0aW9uLmZldGNoRnJvbUlzc3Vlcihpc3N1ZXIsIHJlcXVlc3Rvcik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBjb25maWd1cmF0aW9uID0gbmV3IEF1dGhvcml6YXRpb25TZXJ2aWNlQ29uZmlndXJhdGlvbihzZXJ2aWNlQ29uZmlndXJhdGlvbik7XG4gICAgICB9XG5cbiAgICAgIGF1dGhvcml6YXRpb25IYW5kbGVyLnNldEF1dGhvcml6YXRpb25Ob3RpZmllcihub3RpZmllcik7XG5cbiAgICAgIG5vdGlmaWVyLnNldEF1dGhvcml6YXRpb25MaXN0ZW5lcihhc3luYyAocmVxdWVzdCwgcmVzcG9uc2UsIGVycm9yKSA9PiB7XG4gICAgICAgIGNvbnNvbGUubG9nKCdBdXRob3JpemF0aW9uIHJlcXVlc3QgY29tcGxldGUgJywgcmVxdWVzdCwgcmVzcG9uc2UsIGVycm9yKTtcbiAgICAgICAgaWYgKHJlc3BvbnNlKSB7XG4gICAgICAgICAgbGV0IGNvZGUgPSByZXNwb25zZS5jb2RlO1xuICAgICAgICAgIGxldCB0b2tlbkhhbmRsZXIgPSBuZXcgQmFzZVRva2VuUmVxdWVzdEhhbmRsZXIocmVxdWVzdG9yKTtcblxuICAgICAgICAgIGxldCBfcmVxdWVzdDogVG9rZW5SZXF1ZXN0IHwgbnVsbCA9IG51bGw7XG5cbiAgICAgICAgICBpZiAoY29kZSkge1xuICAgICAgICAgICAgLy8gdXNlIHRoZSBjb2RlIHRvIG1ha2UgdGhlIHRva2VuIHJlcXVlc3QuXG4gICAgICAgICAgICBfcmVxdWVzdCA9IG5ldyBUb2tlblJlcXVlc3Qoe1xuICAgICAgICAgICAgICBjbGllbnRfaWQ6IGNsaWVudElkLFxuICAgICAgICAgICAgICByZWRpcmVjdF91cmk6IHJlZGlyZWN0VXJsLFxuICAgICAgICAgICAgICBncmFudF90eXBlOiBHUkFOVF9UWVBFX0FVVEhPUklaQVRJT05fQ09ERSxcbiAgICAgICAgICAgICAgY29kZTogY29kZSxcbiAgICAgICAgICAgICAgcmVmcmVzaF90b2tlbjogdW5kZWZpbmVkLFxuICAgICAgICAgICAgICBleHRyYXMsXG4gICAgICAgICAgICB9KTtcblxuICAgICAgICAgICAgZXh0cmFzWydjb2RlX3ZlcmlmaWVyJ10gPSByZXF1ZXN0LmludGVybmFsWydjb2RlX3ZlcmlmaWVyJ107XG5cbiAgICAgICAgICAgIGxldCByZXNwb25zZSA9IGF3YWl0IHRva2VuSGFuZGxlci5wZXJmb3JtVG9rZW5SZXF1ZXN0KGNvbmZpZ3VyYXRpb24sIF9yZXF1ZXN0KTtcbiAgICAgICAgICAgIHJlc29sdmUocmVzcG9uc2UpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfSk7XG5cbiAgICAgIGlmIChpc1JlZGlyZWN0KSB7XG4gICAgICAgIGlmIChhd2FpdCBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShcImFwcGF1dGhfY3VycmVudF9hdXRob3JpemF0aW9uX3JlcXVlc3RcIikpIHtcbiAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgYXdhaXQgYXV0aG9yaXphdGlvbkhhbmRsZXIuY29tcGxldGVBdXRob3JpemF0aW9uUmVxdWVzdElmUG9zc2libGUoKVxuICAgICAgICAgIH0gY2F0Y2goZXJyKSB7XG4gICAgICAgICAgICByZWplY3QoZXJyKVxuICAgICAgICAgIH0gZmluYWxseSB7XG4gICAgICAgICAgICByZXR1cm5cbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgcmVqZWN0KClcbiAgICAgICAgcmV0dXJuXG4gICAgICB9XG5cblxuICAgICAgLy8gY3JlYXRlIGEgcmVxdWVzdFxuICAgICAgbGV0IHJlcXVlc3QgPSBuZXcgQXV0aG9yaXphdGlvblJlcXVlc3Qoe1xuICAgICAgICBjbGllbnRfaWQ6IGNsaWVudElkLFxuICAgICAgICByZWRpcmVjdF91cmk6IHJlZGlyZWN0VXJsLFxuICAgICAgICBzY29wZTogc2NvcGVzLmpvaW4oJyAnKSxcbiAgICAgICAgcmVzcG9uc2VfdHlwZTogQXV0aG9yaXphdGlvblJlcXVlc3QuUkVTUE9OU0VfVFlQRV9DT0RFLFxuICAgICAgICBzdGF0ZTogdW5kZWZpbmVkLFxuICAgICAgICBleHRyYXMsXG4gICAgICB9KTtcblxuICAgICAgLy8gbWFrZSB0aGUgYXV0aG9yaXphdGlvbiByZXF1ZXN0XG4gICAgICBhdXRob3JpemF0aW9uSGFuZGxlci5wZXJmb3JtQXV0aG9yaXphdGlvblJlcXVlc3QoY29uZmlndXJhdGlvbiwgcmVxdWVzdCk7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICBjb25zb2xlLmxvZyhlcnIpO1xuICAgICAgcmVqZWN0KGVycik7XG4gICAgfVxuICB9KTtcblxuXG5leHBvcnQgY2xhc3MgTm9IYXNoUXVlcnlTdHJpbmdVdGlscyBleHRlbmRzIEJhc2ljUXVlcnlTdHJpbmdVdGlscyB7XG4gIHBhcnNlKGlucHV0OiBMb2NhdGlvbkxpa2UsIHVzZUhhc2g/OiBib29sZWFuKTogU3RyaW5nTWFwIHtcbiAgICByZXR1cm4gc3VwZXIucGFyc2UoaW5wdXQsIGZhbHNlIC8qIG5ldmVyIHVzZSBoYXNoICovKTtcbiAgfVxufSJdfQ==