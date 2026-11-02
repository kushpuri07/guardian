const video = document.getElementById('bgVideo');
const videoContainer = document.getElementById('scrollVideo');

if (!video || !videoContainer) {
  console.warn('Video elements not found');
}

let videoReady = false;
let lastProgress = -1;
let pendingSeek = false;

function updateVideoTime() {
  if (!videoReady) return;

  const scrollTop = window.scrollY || document.documentElement.scrollTop;
  const docHeight = document.documentElement.scrollHeight - window.innerHeight;
  const progress = Math.min(Math.max(scrollTop / docHeight, 0), 1);

  // Only seek if progress changed meaningfully (avoid micro-updates)
  if (Math.abs(progress - lastProgress) < 0.001) return;
  lastProgress = progress;

  const targetTime = progress * video.duration;

  if (video.readyState < 2) return;

  // Use requestVideoFrameCallback for frame-accurate seeking (modern browsers)
  if (typeof video.requestVideoFrameCallback === 'function') {
    if (pendingSeek) return;
    pendingSeek = true;
    video.currentTime = targetTime;
    video.requestVideoFrameCallback(() => {
      pendingSeek = false;
    });
  } else {
    // Fallback: direct seek with slight throttle
    video.currentTime = targetTime;
  }
}

function onScroll() {
  // Throttle to ~30fps max
  if (window._scrollVideoRaf) return;
  window._scrollVideoRaf = requestAnimationFrame(() => {
    updateVideoTime();
    window._scrollVideoRaf = null;
  });
}

function initVideoScrub() {
  if (videoReady) return;

  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    video.pause();
    video.currentTime = 0;
    videoContainer.classList.add('fallback');
    return;
  }

  video.muted = true;
  video.playsInline = true;
  video.pause();
  video.currentTime = 0;

  const tryInit = () => {
    if (video.readyState >= 2) {
      videoReady = true;
      // Force load first frame
      video.currentTime = 0;
      window.addEventListener('scroll', onScroll, { passive: true });
      updateVideoTime();
    } else {
      setTimeout(tryInit, 100);
    }
  };

  if (video.readyState >= 2) {
    tryInit();
  } else {
    video.addEventListener('loadeddata', tryInit, { once: true });
    video.addEventListener('canplay', tryInit, { once: true });
    setTimeout(tryInit, 2000);
  }

  video.addEventListener('error', () => {
    videoContainer.classList.add('fallback');
    window.removeEventListener('scroll', onScroll);
  });
}

if (video) {
  initVideoScrub();
}

window.addEventListener('resize', () => {
  if (videoReady) updateVideoTime();
});

window.initVideoScrub = initVideoScrub;