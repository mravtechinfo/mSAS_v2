/**
 * mSAS v2 — Event-Driven State Store (BASE-3)
 *
 * Lightweight Pub/Sub state store so UI reacts to state changes
 * instead of manually updating DOM.
 *
 * Usage:
 *   var store = MSAS.StateStore.instance();
 *   store.setState('findings', { items: [...] });
 *   store.subscribe('findings', function(newVal, oldVal) { ... });
 *   store.getState('findings'); // { items: [...] }
 */

var MSAS = MSAS || {};

MSAS.StateStore = (function () {
  'use strict';

  // ── Internal State ──────────────────────────────────────────────────────────
  // Singleton instance
  var _instance = null;

  // State tree: { key: value }
  var _state = {};

  // Subscribers: { key: Set<function> }
  // Also supports wildcard '*' for any change
  var _subscribers = {};

  // Middleware chain: Array<function(key, newVal, oldVal)>
  var _middleware = [];

  // Subscription ID counter for unsubscribe
  var _subIdCounter = 0;
  // { subId: { key, fn } }
  var _subFns = {};

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Get the singleton store instance.
   * @returns {Object} Store API
   */
  function instance() {
    if (!_instance) {
      _instance = Object.freeze({
        getState:       getState,
        setState:       setState,
        subscribe:      subscribe,
        unsubscribe:    unsubscribe,
        clear:          clear,
        getKeys:        getKeys,
        getSnapshot:    getSnapshot,
        addMiddleware:  addMiddleware,
        removeMiddleware: removeMiddleware,
        destroy:        destroy,
        hasState:       hasState,
        on:             subscribe,       // alias
        off:            unsubscribe,     // alias
        emit:           emit
      });
    }
    return _instance;
  }

  /**
   * Get a value from the state tree.
   * @param {string} key - Dot-notation key (e.g., 'findings.items')
   * @returns {*} The stored value, or undefined
   */
  function getState(key) {
    if (key == null) return undefined;
    return resolvePath(_state, key);
  }

  /**
   * Check if a key exists in the state tree.
   * @param {string} key - Dot-notation key
   * @returns {boolean}
   */
  function hasState(key) {
    return getState(key) !== undefined;
  }

  /**
   * Set a value in the state tree and notify subscribers.
   *
   * Triggers:
   *   1. Middleware chain (pre-set hooks)
   *   2. State mutation
   *   3. Subscribers for the specific key
   *   4. Subscribers for each ancestor key
   *   5. Wildcard '*' subscribers
   *
   * @param {string} key - Dot-notation key (e.g., 'findings.items')
   * @param {*} value - Value to store
   * @returns {boolean} true if state changed, false if unchanged
   */
  function setState(key, value) {
    if (key == null) return false;

    var oldVal = resolvePath(_state, key);

    // Run middleware chain (may transform or veto)
    var middlewareResult = runMiddleware(key, value, oldVal);
    if (middlewareResult.vetoed) {
      // Middleware vetoed the change
      return false;
    }
    // Allow middleware to transform the value
    var newVal = middlewareResult.value;

    // Short-circuit if nothing changed (by reference for objects)
    if (newVal === oldVal) return false;

    // Mutate state
    setPath(_state, key, newVal);

    // Notify the specific key subscribers
    notify(key, newVal, oldVal);

    // Notify ancestor wildcards (e.g., set 'findings.items' -> notify 'findings')
    notifyAncestors(key, newVal, oldVal);

    // Notify global wildcard subscribers
    notify('*', newVal, oldVal);

    return true;
  }

  /**
   * Subscribe to changes on a key.
   * @param {string} key - Key to watch (supports '*' for all changes)
   * @param {function(newVal, oldVal, key)} fn - Callback
   * @returns {number} subscription ID (for unsubscribe)
   */
  function subscribe(key, fn) {
    if (typeof fn !== 'function') return -1;
    if (!_subscribers[key]) {
      _subscribers[key] = new Set();
    }
    _subscribers[key].add(fn);

    var subId = ++_subIdCounter;
    _subFns[subId] = { key: key, fn: fn };
    return subId;
  }

  /**
   * Unsubscribe by subscription ID or by function reference.
   * @param {number|function} idOrFn - Subscription ID or the callback function
   * @returns {boolean} true if unsubscribed
   */
  function unsubscribe(idOrFn) {
    if (typeof idOrFn === 'number' && _subFns[idOrFn]) {
      var entry = _subFns[idOrFn];
      if (_subscribers[entry.key]) {
        _subscribers[entry.key].delete(entry.fn);
      }
      delete _subFns[idOrFn];
      return true;
    }

    // Try function reference
    if (typeof idOrFn === 'function') {
      for (var key in _subscribers) {
        if (_subscribers[key].has(idOrFn)) {
          _subscribers[key].delete(idOrFn);
        }
      }
      // Clean up _subFns
      for (var sid in _subFns) {
        if (_subFns[sid].fn === idOrFn) {
          delete _subFns[sid];
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Manually emit an event to subscribers (without changing state).
   * Useful for signalling events that don't carry state.
   * @param {string} key - Event key
   * @param {*} [data] - Optional event data
   */
  function emit(key, data) {
    if (key == null) return;
    notify(key, data, undefined);
    notify('*', data, undefined);
  }

  /**
   * Clear all state (optionally preserve certain keys).
   * @param {string[]} [preserveKeys] - Keys to keep
   */
  function clear(preserveKeys) {
    var preserve = preserveKeys || [];
    var preserved = {};
    for (var i = 0; i < preserve.length; i++) {
      var pk = preserve[i];
      if (pk) preserved[pk] = resolvePath(_state, pk);
    }
    _state = {};
    // Restore preserved keys
    for (var pk2 in preserved) {
      setPath(_state, pk2, preserved[pk2]);
    }
    notify('*', _state, undefined);
  }

  /**
   * Get all top-level state keys.
   * @returns {string[]}
   */
  function getKeys() {
    return Object.keys(_state);
  }

  /**
   * Get a snapshot of the entire state tree (shallow clone).
   * @returns {Object}
   */
  function getSnapshot() {
    return shallowClone(_state);
  }

  /**
   * Add a middleware function.
   * Middleware is called before each setState with (key, newVal, oldVal).
   * Return false to veto the change, or return a value to transform it.
   * Return undefined to allow the change as-is.
   * @param {function} fn
   * @returns {boolean}
   */
  function addMiddleware(fn) {
    if (typeof fn !== 'function') return false;
    _middleware.push(fn);
    return true;
  }

  /**
   * Remove a middleware function.
   * @param {function} fn
   * @returns {boolean}
   */
  function removeMiddleware(fn) {
    var idx = _middleware.indexOf(fn);
    if (idx >= 0) {
      _middleware.splice(idx, 1);
      return true;
    }
    return false;
  }

  /**
   * Destroy the store — clear all state and unsubscribe everything.
   */
  function destroy() {
    _state = {};
    _subscribers = {};
    _subFns = {};
    _middleware = [];
    _instance = null;
  }

  // ── Internal Helpers ────────────────────────────────────────────────────────

  /**
   * Resolve a dot-notation path in an object.
   */
  function resolvePath(obj, path) {
    if (!obj || !path) return undefined;
    var parts = path.split('.');
    var current = obj;
    for (var i = 0; i < parts.length; i++) {
      if (current == null || typeof current !== 'object') return undefined;
      current = current[parts[i]];
    }
    return current;
  }

  /**
   * Set a value at a dot-notation path, creating intermediate objects as needed.
   */
  function setPath(obj, path, value) {
    var parts = path.split('.');
    var current = obj;
    for (var i = 0; i < parts.length - 1; i++) {
      if (current[parts[i]] == null || typeof current[parts[i]] !== 'object') {
        current[parts[i]] = {};
      }
      current = current[parts[i]];
    }
    current[parts[parts.length - 1]] = value;
  }

  /**
   * Run all middleware functions.
   * Middleware can return false to veto the change, or return a transformed value.
   * Return undefined to leave the value unchanged.
   * 
   * Returns { value: * } on success, { vetoed: true } if vetoed.
   * This avoids conflating false-as-value with false-as-veto.
   *
   * @param {string} key
   * @param {*} newVal
   * @param {*} oldVal
   * @returns {{value:*}|{vetoed:boolean}}
   */
  function runMiddleware(key, newVal, oldVal) {
    var vetoed = false;
    var val = newVal;
    for (var i = 0; i < _middleware.length; i++) {
      var result = _middleware[i](key, val, oldVal);
      if (result === false) {
        vetoed = true;
        break;
      }
      if (result !== undefined) val = result;
    }
    if (vetoed) return { vetoed: true };
    return { value: val };
  }

  /**
   * Notify subscribers for a specific key.
   */
  function notify(key, newVal, oldVal) {
    var subs = _subscribers[key];
    if (!subs || subs.size === 0) return;
    // Iterate over a copy to avoid issues if a subscriber unsubscribes during iteration
    var fns = Array.from(subs);
    for (var i = 0; i < fns.length; i++) {
      try {
        fns[i](newVal, oldVal, key);
      } catch (e) {
        console.warn('[StateStore] subscriber error for "' + key + '":', e);
      }
    }
  }

  /**
   * Notify subscribers of ancestor keys.
   * e.g., setting 'findings.items' also notifies 'findings'
   */
  function notifyAncestors(key, newVal, oldVal) {
    var parts = key.split('.');
    for (var i = parts.length - 1; i > 0; i--) {
      var ancestorKey = parts.slice(0, i).join('.');
      var ancestorVal = resolvePath(_state, ancestorKey);
      notify(ancestorKey, ancestorVal, undefined);
    }
  }

  /**
   * Shallow clone an object.
   */
  function shallowClone(obj) {
    if (obj == null || typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.slice();
    var clone = {};
    for (var key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        clone[key] = obj[key];
      }
    }
    return clone;
  }

  // ── Module Export ───────────────────────────────────────────────────────────

  return {
    instance: instance,
    // Direct access for testing without singleton
    _reset: function () {
      _state = {};
      _subscribers = {};
      _subFns = {};
      _middleware = [];
      _instance = null;
    }
  };
})();
