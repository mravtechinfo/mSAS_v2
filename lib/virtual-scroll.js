/**
 * mSAS v2 — Virtual Scrolling Engine
 * 
 * Efficient rendering of large finding lists using virtual scrolling.
 * Only renders visible items + overscan buffer.
 * Part of Phase 8: UX Polish (UX-10).
 */

var MSAS = MSAS || {};

MSAS.VirtualScroll = (function() {
  'use strict';

  /**
   * Create a virtual scroll controller.
   * @param {Object} opts
   * @param {HTMLElement} opts.container - Scroll container element
   * @param {number} opts.itemHeight - Height of each item in px
   * @param {number} opts.overscan - Extra items to render above/below viewport
   * @param {Function} opts.renderItem - Function(item, index) => HTML string
   * @param {Array} opts.items - Full array of items
   * @param {Function} [opts.onVisibleRangeChange] - Callback when visible range changes
   * @returns {Object} controller with { update, destroy, scrollToIndex }
   */
  function create(opts) {
    if (!opts.container) return null;

    var container = opts.container;
    var itemHeight = opts.itemHeight || 36;
    var overscan = opts.overscan || 5;
    var renderItem = opts.renderItem || function() { return ''; };
    var items = opts.items || [];
    var onVisibleRangeChange = opts.onVisibleRangeChange || null;

    // Create inner spacer element
    var spacer = document.createElement('div');
    spacer.className = 'virtual-scroll-spacer';
    spacer.style.cssText = 'pointer-events:none;';
    container.style.overflowY = 'auto';
    container.style.position = 'relative';
    container.appendChild(spacer);

    // Create viewport element
    var viewport = document.createElement('div');
    viewport.className = 'virtual-scroll-viewport';
    viewport.style.cssText = 'position:relative;width:100%;';
    container.appendChild(viewport);

    var totalHeight = items.length * itemHeight;
    var lastRender = -1;
    var rafId = null;

    function updateScroll() {
      if (rafId) return;
      rafId = requestAnimationFrame(function() {
        rafId = null;
        renderVisible();
      });
    }

    function renderVisible() {
      var scrollTop = container.scrollTop;
      var viewportHeight = container.clientHeight;

      var startIdx = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan);
      var endIdx = Math.min(items.length, Math.ceil((scrollTop + viewportHeight) / itemHeight) + overscan);

      if (startIdx === lastRender && items.length > 0) return;

      // Update spacer height
      totalHeight = items.length * itemHeight;
      spacer.style.height = totalHeight + 'px';

      // Render visible items
      var fragment = document.createDocumentFragment();
      var topOffset = startIdx * itemHeight;

      for (var i = startIdx; i < endIdx; i++) {
        var itemEl = document.createElement('div');
        itemEl.className = 'virtual-scroll-item';
        itemEl.style.cssText = 'position:absolute;top:' + (i * itemHeight - topOffset) + 'px;left:0;right:0;height:' + itemHeight + 'px;';
        itemEl.dataset.index = i;
        itemEl.innerHTML = renderItem(items[i], i);
        fragment.appendChild(itemEl);
      }

      viewport.innerHTML = '';
      viewport.style.top = topOffset + 'px';
      viewport.appendChild(fragment);
      lastRender = startIdx;

      if (onVisibleRangeChange) {
        onVisibleRangeChange({ start: startIdx, end: endIdx });
      }
    }

    // Bind scroll event
    container.addEventListener('scroll', updateScroll, { passive: true });
    window.addEventListener('resize', updateScroll, { passive: true });

    // Initial render
    renderVisible();

    return {
      /**
       * Update with new items array.
       */
      update: function(newItems) {
        items = newItems;
        totalHeight = items.length * itemHeight;
        lastRender = -1;
        renderVisible();
      },

      /**
       * Scroll to a specific index.
       */
      scrollToIndex: function(index) {
        index = Math.max(0, Math.min(items.length - 1, index));
        container.scrollTop = index * itemHeight;
        renderVisible();
      },

      /**
       * Clean up event listeners.
       */
      destroy: function() {
        container.removeEventListener('scroll', updateScroll);
        window.removeEventListener('resize', updateScroll);
        if (rafId) {
          cancelAnimationFrame(rafId);
          rafId = null;
        }
        viewport.innerHTML = '';
        spacer.innerHTML = '';
      },

      /**
       * Get current visible range.
       */
      getVisibleRange: function() {
        var scrollTop = container.scrollTop;
        var viewportHeight = container.clientHeight;
        return {
          start: Math.max(0, Math.floor(scrollTop / itemHeight)),
          end: Math.min(items.length, Math.ceil((scrollTop + viewportHeight) / itemHeight))
        };
      }
    };
  }

  return {
    create: create
  };
})();
