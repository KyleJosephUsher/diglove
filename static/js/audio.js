const ringtone = new Audio('/static/audio/ringtone.mp3');
ringtone.loop = true;

function playRingtone() {
  ringtone.play().catch(error => {
    console.error("Ringtone playback error:", error);
  });
}

function stopRingtone() {
  ringtone.pause();
  ringtone.currentTime = 0;
}