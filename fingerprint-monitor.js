(function() {
  function emit(detail) {
    document.dispatchEvent(new CustomEvent('__privacyScannerFingerprint', { detail: detail }));
  }

  try {
    var origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function() {
      emit({ type: 'canvas_toDataURL', timestamp: Date.now() });
      return origToDataURL.apply(this, arguments);
    };

    var origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function() {
      emit({ type: 'canvas_getImageData', timestamp: Date.now() });
      return origGetImageData.apply(this, arguments);
    };
  } catch(e) {}

  try {
    var origGetContext = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function(type) {
      var t = (type || '').toLowerCase();
      if (t === 'webgl' || t === 'experimental-webgl' || t === 'webgl2') {
        emit({ type: 'webgl_context_creation', contextType: type, timestamp: Date.now() });
      }
      return origGetContext.apply(this, arguments);
    };
  } catch(e) {}

  try {
    var AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (AudioCtx) {
      var origOsc = AudioCtx.prototype.createOscillator;
      var origAnalyser = AudioCtx.prototype.createAnalyser;
      AudioCtx.prototype.createOscillator = function() {
        emit({ type: 'audio_oscillator', timestamp: Date.now() });
        return origOsc.apply(this, arguments);
      };
      AudioCtx.prototype.createAnalyser = function() {
        emit({ type: 'audio_analyser', timestamp: Date.now() });
        return origAnalyser.apply(this, arguments);
      };
    }
  } catch(e) {}
})();
