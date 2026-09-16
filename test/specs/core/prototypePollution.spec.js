var utils = require('../../../lib/utils');
var mergeConfig = require('../../../lib/core/mergeConfig');
var defaults = require('../../../lib/defaults');

describe('Prototype Pollution Protection', function() {
  afterEach(function() {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
    delete Object.prototype.transport;
    delete Object.prototype.transformRequest;
    delete Object.prototype.transformResponse;
    delete Object.prototype.formSerializer;
    delete Object.prototype.env;
    delete Object.prototype.parseReviver;
    delete Object.prototype.adapter;
    delete Object.prototype.validateStatus;
    delete Object.prototype.data;
  });

  describe('utils.merge', function() {
    it('should filter __proto__ key at top level', function() {
      var result = utils.merge({}, {__proto__: {polluted: 'yes'}, safe: 'value'});

      expect(Object.prototype.polluted).toBeUndefined();
      expect(result.safe).toEqual('value');
      expect(result.hasOwnProperty('__proto__')).toBe(false);
    });

    it('should filter constructor key at top level', function() {
      var result = utils.merge({}, {constructor: {polluted: 'yes'}, safe: 'value'});

      expect(result.safe).toEqual('value');
      expect(result.hasOwnProperty('constructor')).toBe(false);
    });

    it('should filter prototype key at top level', function() {
      var result = utils.merge({}, {prototype: {polluted: 'yes'}, safe: 'value'});

      expect(result.safe).toEqual('value');
      expect(result.hasOwnProperty('prototype')).toBe(false);
    });

    it('should filter __proto__ key in nested objects', function() {
      var result = utils.merge({}, {
        headers: {
          __proto__: {polluted: 'nested'},
          'Content-Type': 'application/json'
        }
      });

      expect(Object.prototype.polluted).toBeUndefined();
      expect(result.headers['Content-Type']).toEqual('application/json');
      expect(result.headers.hasOwnProperty('__proto__')).toBe(false);
    });

    it('should filter constructor key in nested objects', function() {
      var result = utils.merge({}, {
        headers: {
          constructor: {prototype: {polluted: 'nested'}},
          'Content-Type': 'application/json'
        }
      });

      expect(Object.prototype.polluted).toBeUndefined();
      expect(result.headers['Content-Type']).toEqual('application/json');
      expect(result.headers.hasOwnProperty('constructor')).toBe(false);
    });

    it('should filter prototype key in nested objects', function() {
      var result = utils.merge({}, {
        headers: {
          prototype: {polluted: 'nested'},
          'Content-Type': 'application/json'
        }
      });

      expect(result.headers['Content-Type']).toEqual('application/json');
      expect(result.headers.hasOwnProperty('prototype')).toBe(false);
    });

    it('should filter dangerous keys in deeply nested objects', function() {
      var result = utils.merge({}, {
        level1: {
          level2: {
            __proto__: {polluted: 'deep'},
            prototype: {polluted: 'deep'},
            safe: 'value'
          }
        }
      });

      expect(Object.prototype.polluted).toBeUndefined();
      expect(result.level1.level2.safe).toEqual('value');
      expect(result.level1.level2.hasOwnProperty('__proto__')).toBe(false);
    });

    it('should still merge regular properties correctly', function() {
      var result = utils.merge({a: 1, b: {c: 2}}, {b: {d: 3}, e: 4});

      expect(result.a).toEqual(1);
      expect(result.b.c).toEqual(2);
      expect(result.b.d).toEqual(3);
      expect(result.e).toEqual(4);
    });

    it('should handle JSON.parse payloads safely', function() {
      var malicious = JSON.parse('{"__proto__": {"polluted": "yes"}}');
      var result = utils.merge({}, malicious);

      expect(Object.prototype.polluted).toBeUndefined();
      expect(result.hasOwnProperty('__proto__')).toBe(false);
    });

    it('should handle nested JSON.parse payloads safely', function() {
      var malicious = JSON.parse('{"headers": {"constructor": {"prototype": {"polluted": "yes"}}}}');
      var result = utils.merge({}, malicious);

      expect(Object.prototype.polluted).toBeUndefined();
      expect(result.headers.hasOwnProperty('constructor')).toBe(false);
    });
  });

  describe('mergeConfig', function() {
    it('should filter dangerous keys at top level', function() {
      var result = mergeConfig({}, {
        __proto__: {polluted: 'yes'},
        constructor: {polluted: 'yes'},
        prototype: {polluted: 'yes'},
        url: '/api/test'
      });

      expect(Object.prototype.polluted).toBeUndefined();
      expect(result.url).toEqual('/api/test');
      expect(result.hasOwnProperty('__proto__')).toBe(false);
      expect(result.hasOwnProperty('constructor')).toBe(false);
      expect(result.hasOwnProperty('prototype')).toBe(false);
    });

    it('should filter dangerous keys in headers', function() {
      var result = mergeConfig({}, {
        headers: {
          __proto__: {polluted: 'yes'},
          'Content-Type': 'application/json'
        }
      });

      expect(Object.prototype.polluted).toBeUndefined();
      expect(result.headers['Content-Type']).toEqual('application/json');
      expect(result.headers.hasOwnProperty('__proto__')).toBe(false);
    });

    it('should filter dangerous keys in custom config properties', function() {
      var result = mergeConfig({}, {
        customProp: {
          __proto__: {polluted: 'yes'},
          safe: 'value'
        }
      });

      expect(Object.prototype.polluted).toBeUndefined();
      expect(result.customProp.safe).toEqual('value');
      expect(result.customProp.hasOwnProperty('__proto__')).toBe(false);
    });

    it('should not inherit transport from Object.prototype', function() {
      Object.prototype.transport = {request: function() {}};

      var result = mergeConfig({}, {url: '/a'});

      expect(Object.prototype.hasOwnProperty.call(result, 'transport')).toBe(false);
    });

    it('should not inherit transformRequest from Object.prototype', function() {
      Object.prototype.transformRequest = function() { return 'hijacked'; };

      var result = mergeConfig({}, {url: '/a'});

      expect(Object.prototype.hasOwnProperty.call(result, 'transformRequest')).toBe(false);
    });

    it('should not inherit transformResponse from Object.prototype', function() {
      Object.prototype.transformResponse = function() { return 'hijacked'; };

      var result = mergeConfig({}, {url: '/a'});

      expect(Object.prototype.hasOwnProperty.call(result, 'transformResponse')).toBe(false);
    });

    it('should not inherit arbitrary keys from Object.prototype', function() {
      Object.prototype.polluted = 'yes';

      var result = mergeConfig({}, {url: '/a'});

      expect(Object.prototype.hasOwnProperty.call(result, 'polluted')).toBe(false);
    });

    // The merge map walks every own key of either config, so a key owned by the
    // defaults (config1) is visited even when the request config (config2) only
    // inherits it. Without own-property guards the inherited value wins.
    it('should not let an inherited transformRequest override the configured one', function() {
      var original = function original() { return 'original'; };
      Object.prototype.transformRequest = function polluted() { return 'hijacked'; };

      var result = mergeConfig({transformRequest: original}, {url: '/a'});

      expect(result.transformRequest).toBe(original);
      expect(result.transformRequest()).toEqual('original');
    });

    it('should not let an inherited transformResponse override the configured one', function() {
      var original = function original() { return 'original'; };
      Object.prototype.transformResponse = function polluted() { return 'hijacked'; };

      var result = mergeConfig({transformResponse: original}, {url: '/a'});

      expect(result.transformResponse).toBe(original);
      expect(result.transformResponse()).toEqual('original');
    });

    it('should not let an inherited adapter override the configured adapter', function() {
      var original = function original() {};
      Object.prototype.adapter = function polluted() {};

      var result = mergeConfig({adapter: original}, {url: '/a'});

      expect(result.adapter).toBe(original);
    });

    it('should not let an inherited transport override the configured transport', function() {
      var original = function original() {};
      Object.prototype.transport = function polluted() {};

      var result = mergeConfig({transport: original}, {url: '/a'});

      expect(result.transport).toBe(original);
    });

    // validateStatus is merged with mergeDirectKeys, which used to probe the
    // whole prototype chain with `prop in config`.
    it('should not let an inherited validateStatus override the configured one', function() {
      var original = function original(status) { return status === 200; };
      Object.prototype.validateStatus = function polluted() { return true; };

      var result = mergeConfig({validateStatus: original}, {url: '/a'});

      expect(result.validateStatus).toBe(original);
      expect(result.validateStatus(500)).toBe(false);
    });

    it('should not let an inherited env override the configured env', function() {
      var ownFormData = function OwnFormData() {};
      Object.prototype.env = {FormData: function PollutedFormData() {}};

      var result = mergeConfig({env: {FormData: ownFormData}}, {url: '/a'});

      expect(result.env.FormData).toBe(ownFormData);
    });

    it('should not take an inherited value for a config2-only key', function() {
      Object.prototype.data = 'polluted';

      var result = mergeConfig({data: 'own'}, {url: '/a'});

      expect(Object.prototype.hasOwnProperty.call(result, 'data')).toBe(false);
    });

    it('should still merge configs correctly', function() {
      var config1 = {
        baseURL: 'https://api.example.com',
        timeout: 1000,
        headers: {
          common: {
            Accept: 'application/json'
          }
        }
      };

      var config2 = {
        url: '/users',
        timeout: 5000,
        headers: {
          common: {
            'Content-Type': 'application/json'
          }
        }
      };

      var result = mergeConfig(config1, config2);

      expect(result.baseURL).toEqual('https://api.example.com');
      expect(result.url).toEqual('/users');
      expect(result.timeout).toEqual(5000);
      expect(result.headers.common.Accept).toEqual('application/json');
      expect(result.headers.common['Content-Type']).toEqual('application/json');
    });
  });

  describe('defaults.transformRequest', function() {
    it('should not use a FormData constructor inherited from Object.prototype', function() {
      var used = false;

      function PollutedFormData() {
        used = true;
      }
      PollutedFormData.prototype.append = function append() {};

      Object.prototype.env = {FormData: PollutedFormData};

      var result = defaults.transformRequest[0]({x: 1}, {'Content-Type': 'multipart/form-data'});

      expect(used).toBe(false);
      expect(result instanceof PollutedFormData).toBe(false);
      expect(result).toEqual(jasmine.any(FormData));
    });
  });
});
