/**
 * Module dependencies.
 */
var utils = require('../utils')
  , TokenError = require('../errors/tokenerror');


/**
 * Exchanges an access token for a chained access token.
 *
 * This exchange is used to by a protected service to exchange a token it
 * receives from a client for a token it can use to access another protected
 * service.  This scenario facilitiates service chaining.
 *
 * Note that their are critical security implications when passing an access
 * token between separate security domains.  Trust must be established between
 * the domains so that the issuer of the token can be determined, and the token
 * itself can be validated.  Furthermore, there must be a method of mapping the
 * subject in the issuing domain to a subject in the target domain.  These
 * mechanisms are not within the scope of this grant type (or this Node
 * package), and must be defined and implemented by the application.
 *
 * References:
 *  - [Chain Grant Type for OAuth2](http://tools.ietf.org/html/draft-hunt-oauth-chain-01)
 *  - [Refresh of chaining draft](http://www.ietf.org/mail-archive/web/oauth/current/msg10166.html)
 *
 * @param {Object} options
 * @param {Function} issue
 * @return {Function}
 * @api public
 */
module.exports = function(options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};
  
  if (!issue) { throw new TypeError('oauth2orize-chain exchange requires an issue callback'); }
  
  var userProperty = options.userProperty || 'user';
  
  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [ separators ];
  }
  
  return function chain(req, res, next) {
    if (!req.body) { return next(new Error('OAuth2orize requires body parsing. Did you forget app.use(express.bodyParser())?')); }
    
    // The 'user' property of `req` holds the authenticated user.  In the case
    // of the token endpoint, the property will contain the OAuth 2.0 client.
    var client = req[userProperty]
      , token = req.body.oauth_token
      , scope = req.body.scope;
      
    if (!token) { return next(new TokenError('Missing required parameter: oauth_token', 'invalid_request')); }
  
    var parts = token.split(' ');
    if (parts.length != 2) { return next(new TokenError('Malformed parameter: oauth_token', 'invalid_request')); }
      
    var scheme = parts[0]
      , credential = parts[1];
  
    if (scope) {
      for (var i = 0, len = separators.length; i < len; i++) {
        var separated = scope.split(separators[i]);
        // only separate on the first matching separator.  this allows for a sort
        // of separator "priority" (ie, favor spaces then fallback to commas)
        if (separated.length > 1) {
          scope = separated;
          break;
        }
      }
      if (!Array.isArray(scope)) { scope = [ scope ]; }
    }
    
    function issued(err, accessToken, refreshToken, params) {
      if (err) { return next(err); }
      if (!accessToken) { return next(new TokenError('Invalid OAuth token', 'invalid_grant')); }
      if (refreshToken && typeof refreshToken == 'object') {
        params = refreshToken;
        refreshToken = null;
      }
      
      var tok = {};
      tok.access_token = accessToken;
      // WARNING: The specification states that the token server SHOULD NOT
      // issue refresh tokens.  Because the advice is SHOULD NOT, rather than
      // MUST NOT, this implementation allows refresh tokens to be issued.
      // Before doing so, implementers are encouraged to understand the security
      // concerns around delegation and refresh tokens.
      if (refreshToken) { tok.refresh_token = refreshToken; }
      if (params) { utils.merge(tok, params); }
      tok.token_type = tok.token_type || 'Bearer';
      
      var json = JSON.stringify(tok);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.end(json);
    }
    
    try {
      var arity = issue.length;
      if (arity == 7) {
        issue(client, credential, scheme, scope, req.body, req.authInfo, issued);
      } else {
        if (scheme.toLowerCase() !== 'bearer') {
          return next(new TokenError('Unsupported authorization scheme: ' + scheme, 'invalid_request'));
        }
        
        if (arity == 6) {
          issue(client, credential, scope, req.body, req.authInfo, issued);
        } else if (arity == 5) {
          issue(client, credential, scope, req.body, issued);
        } else if (arity == 4) {
          issue(client, credential, scope, issued);
        } else { // arity == 3
          issue(client, credential, issued);
        }
      }
    } catch (ex) {
      return next(ex);
    }
  };
};
