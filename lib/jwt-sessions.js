'use strict';

/* Handles client sessions using JWT for encoding and verification. Adapted from
 * https://github.com/teamookla/node-jwt-sessions (MPL notice follows) */

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var Cookies = require('cookies');
var jwt = require('jwt-simple');

var COOKIE_NAME_SEP = '=';
var ACTIVE_DURATION = 1000 * 60 * 5;

/* list of supported algorithms */
var ALGORITHMS = {
  'HS256': true,
  'HS384': true,
  'HS512': true,
  'RS256': true
 };
var DEFAULT_ALGORITHM = 'HS256';

function isObject(val) {
  return Object.prototype.toString.call(val) === '[object Object]';
}

function encode(opts, content, duration, createdAt) {
  // adds createdAt and duration to content, then encodes using JWT
  if (!opts.cookieName) {
    throw new Error('cookieName option required');
  } else if (String(opts.cookieName).indexOf(COOKIE_NAME_SEP) !== -1) {
    throw new Error('cookieName cannot include "="');
  }

  return jwt.encode({
    cookieName: opts.cookieName,
    createdAt: createdAt || new Date().getTime(),
    duration: duration || 24 * 60 * 60 * 1000,
    content: content
  }, opts.secret);
}

function decode(opts, token) {
  if (!opts.cookieName) {
    throw new Error("cookieName option required");
  }

  // stop at any time if there's an issue
  try {
    var decoded = jwt.decode(token, opts.secret);
    if (decoded.cookieName !== opts.cookieName) {
      return;
    }
    return decoded;
  } catch (ignored) {
    return;
  }
}

/*
 * Session object
 *
 * this should be implemented with proxies at some point
 */
function Session(req, res, cookies, opts) {
  this.req = req;
  this.res = res;
  this.cookies = cookies;
  this.opts = opts;
  if (opts.cookie.ephemeral && opts.cookie.maxAge) {
    throw new Error('you cannot have an ephemeral cookie with a maxAge.');
  }

  this.content = {};
  this.json = JSON.stringify(this._content);
  this.loaded = false;
  this.dirty = false;

  // no need to initialize it, loadFromCookie will do
  // via reset() or unbox()
  this.createdAt = null;
  this.duration = opts.duration;
  this.activeDuration = opts.activeDuration;

  // support for maxAge
  if (opts.cookie.maxAge) {
    this.expires = new Date(new Date().getTime() + opts.cookie.maxAge);
  } else {
    this.updateDefaultExpires();
  }

  // here, we check that the security bits are set correctly
  var secure = (res.socket && res.socket.encrypted) ||
      (req.connection && req.connection.proxySecure);
  if (opts.cookie.secure && !secure) {
    throw new Error('you cannot have a secure cookie unless the socket is ' +
        ' secure or you declare req.connection.proxySecure to be true.');
  }
}

Session.prototype = {
  updateDefaultExpires: function() {
    if (this.opts.cookie.maxAge) {
      return;
    }

    if (this.opts.cookie.ephemeral) {
      this.expires = null;
    } else {
      var time = this.createdAt || new Date().getTime();
      // the cookie should expire when it becomes invalid
      // we add an extra second because the conversion to a date
      // truncates the milliseconds
      this.expires = new Date(time + this.duration + 1000);
    }
  },

  clearContent: function(keysToPreserve) {
    var _this = this;
    Object.keys(this._content).forEach(function(k) {
      // exclude this key if it's meant to be preserved
      if (keysToPreserve && (keysToPreserve.indexOf(k) > -1)) {
        return;
      }

      delete _this._content[k];
    });
  },

  reset: function(keysToPreserve) {
    this.clearContent(keysToPreserve);
    this.createdAt = new Date().getTime();
    this.duration = this.opts.duration;
    this.updateDefaultExpires();
    this.dirty = true;
    this.loaded = true;
  },

  // alias for `reset` function for compatibility
  destroy: function() {
    this.reset();
  },

  setDuration: function(newDuration, ephemeral) {
    if (ephemeral && this.opts.cookie.maxAge) {
      throw new Error('you cannot have an ephemeral cookie with a maxAge.');
    }
    if (!this.loaded) {
      this.loadFromCookie(true);
    }
    this.dirty = true;
    this.duration = newDuration;
    this.createdAt = new Date().getTime();
    this.opts.cookie.ephemeral = ephemeral;
    this.updateDefaultExpires();
  },

  // take the content and do the encrypt-and-sign
  // boxing builds in the concept of createdAt
  box: function() {
    return encode(this.opts, this._content, this.duration, this.createdAt);
  },

  unbox: function(content) {
    this.clearContent();

    var unboxed = decode(this.opts, content);
    if (!unboxed) {
      return;
    }

    var _this = this;


    Object.keys(unboxed.content).forEach(function(k) {
      _this._content[k] = unboxed.content[k];
    });

    this.createdAt = unboxed.createdAt;
    this.duration = unboxed.duration;
    this.updateDefaultExpires();
  },

  updateCookie: function() {
    if (this.isDirty()) {
      // support for adding/removing cookie expires
      this.opts.cookie.expires = this.expires;

      try {
        this.cookies.set(this.opts.cookieName, this.box(), this.opts.cookie);
      } catch (x) {
        // this really shouldn't happen. Right now it happens if secure is set
        // but cookies can't determine that the connection is secure.
      }
    }
  },

  loadFromCookie: function(forceReset) {
    var cookie = this.cookies.get(this.opts.cookieName);
    if (cookie) {
      this.unbox(cookie);

      var expiresAt = this.createdAt + this.duration;
      var now = Date.now();
      // should we reset this session?
      if (expiresAt < now) {
        this.reset();
      // if expiration is soon, push back a few minutes to not interrupt user
      } else if (expiresAt - now < this.activeDuration) {
        this.createdAt += this.activeDuration;
        this.dirty = true;
        this.updateDefaultExpires();
      }
    } else {
      if (forceReset) {
        this.reset();
      } else {
        return false; // didn't actually load the cookie
      }
    }

    this.loaded = true;
    this.json = JSON.stringify(this._content);
    return true;
  },

  isDirty: function() {
    return this.dirty || (this.json !== JSON.stringify(this._content));
  }

};

Object.defineProperty(Session.prototype, 'content', {
  get: function getContent() {
    if (!this.loaded) {
      this.loadFromCookie();
    }
    return this._content;
  },
  set: function setContent(value) {
    Object.defineProperty(value, 'reset', {
      enumerable: false,
      value: this.reset.bind(this)
    });
    Object.defineProperty(value, 'destroy', {
      enumerable: false,
      value: this.destroy.bind(this)
    });
    Object.defineProperty(value, 'setDuration', {
      enumerable: false,
      value: this.setDuration.bind(this)
    });
    this._content = value;
  }
});

function clientSessionFactory(opts) {
  if (!opts) {
    throw new Error('no options provided, some are required');
  }

  if (!opts.secret) {
    throw new Error('cannot set up sessions without a secret');
  }

  // defaults
  opts.cookieName = opts.cookieName || 'session_state';
  opts.duration = opts.duration || 24 * 60 * 60 * 1000;
  opts.activeDuration = 'activeDuration' in opts ?
    opts.activeDuration : ACTIVE_DURATION;

  var alg = opts.algorithm || DEFAULT_ALGORITHM;
  alg = alg.toUpperCase();
  if (!ALGORITHMS[alg]) {
    throw new Error('invalid algorithm, supported are: ' +
                    Object.keys(ALGORITHMS).join(', '));
  }
  opts.algorithm = alg;

  // set up cookie defaults
  opts.cookie = opts.cookie || {};
  if (typeof opts.cookie.httpOnly === 'undefined') {
    opts.cookie.httpOnly = true;
  }

  var propertyName = opts.requestKey || opts.cookieName;

  return function clientSession(req, res, next) {
    if (propertyName in req) {
      return next(); // self aware
    }

    var cookies = new Cookies(req, res);
    var rawSession;
    try {
      rawSession = new Session(req, res, cookies, opts);
    } catch (x) {
      // this happens only if there's a big problem
      process.nextTick(function() {
        next('jwt-sessions error: ' + x.toString());
      });
      return;
    }

    Object.defineProperty(req, propertyName, {
      get: function getSession() {
        return rawSession.content;
      },
      set: function setSession(value) {
        if (isObject(value)) {
          rawSession.content = value;
        } else {
          throw new TypeError('cannot set jwt-session to non-object');
        }
      }
    });


    var writeHead = res.writeHead;
    res.writeHead = function () {
      rawSession.updateCookie();
      return writeHead.apply(res, arguments);
    };

    next();
  };
}

module.exports = clientSessionFactory;

// Expose encode and decode method

module.exports.util = {
  encode: encode,
  decode: decode
};
