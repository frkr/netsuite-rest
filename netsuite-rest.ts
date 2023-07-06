import CryptoJS, {enc} from "crypto-js";
import OAuth from "oauth-1.0a";

type Options = {
  method?: string
  url?: string
  headers?: any
  body?: any
  path?: string
  heads?: []
}

export default class NetsuiteRest {

  private readonly consumer_key: string;
  private readonly consumer_secret_key: string;
  private readonly token: string;
  private readonly token_secret: string;
  private readonly version: string;
  private readonly algorithm: string;
  private readonly realm: string;
  private readonly base_url: string;

  constructor(options) {
    this.consumer_key = options.consumer_key;
    this.consumer_secret_key = options.consumer_secret_key;
    this.token = options.token;
    this.token_secret = options.token_secret;
    this.version = "1.0";
    this.algorithm = "HMAC-SHA256";
    this.realm = options.realm;
    this.base_url = options.base_url;
  }

  getAuthorizationHeader(options: Options) {
    let oauth = new OAuth({
      consumer: {
        key: this.consumer_key,
        secret: this.consumer_secret_key,
      },
      realm: this.realm,
      signature_method: this.algorithm,
      hash_function(baseString, key) {
        return CryptoJS.HmacSHA256(baseString, key).toString(enc.Base64)
      },
    });
    return oauth.toHeader(
        oauth.authorize(
            {
              url: options.url + "",
              method: options.method + "",
            },
            {
              key: this.token + "",
              secret: this.token_secret + "",
            }
        )
    );
  }

  async request(opts: Options) {
    let {path = "*", method = "GET", body = null, heads = {}} = opts;

    // Setup the Request URI
    let uri;
    if (this.base_url) uri = `${this.base_url}/services/rest/${path}`;
    else {
      // as suggested by dylbarne in #15: sanitize url to enhance overall usability
      uri = `https://${this.realm
          .toLowerCase()
          .replace("_", "-")}.suitetalk.api.netsuite.com/services/rest/${path}`;
    }

    opts.url = uri;
    opts.method = method;

    let headers = this.getAuthorizationHeader(opts);
    if (Object.keys(headers).length > 0) {
      opts.headers = {...headers, ...heads};
    }
    let bd: string = null;
    if (body) {
      bd = JSON.stringify(body);
      opts.headers['prefer'] = "transient";
    }

    let req = {
      method: method,
      headers: opts.headers,
      body: bd,
    }

    if (method === "OPTIONS") {
      return true;
    } else {
      return (await fetch(uri, req)).json();
    }
  }
}
