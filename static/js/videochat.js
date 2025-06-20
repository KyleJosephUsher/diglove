const socket = io();

// Injected from Flask template: room_id must be passed from your route
const room = "{{ room_id }}";

const localVideo = document.getElementById('localVideo');
const remoteVideo = document.getElementById('remoteVideo');
const startCallBtn = document.getElementById('startCallBtn');
const hangupBtn = document.getElementById('hangupBtn');

let localStream;
let peerConnection;

const config = {
  iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
};

async function startLocalStream() {
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
    localVideo.srcObject = localStream;
  } catch (err) {
    alert('Could not get user media: ' + err.message);
  }
}

function createPeerConnection() {
  peerConnection = new RTCPeerConnection(config);

  localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));

  peerConnection.ontrack = event => {
    remoteVideo.srcObject = event.streams[0];
  };

  peerConnection.onicecandidate = event => {
    if (event.candidate) {
      socket.emit('ice-candidate', { candidate: event.candidate, room });
    }
  };
}

startCallBtn.onclick = async () => {
  startCallBtn.disabled = true;
  hangupBtn.disabled = false;

  await startLocalStream();
  createPeerConnection();

  const offer = await peerConnection.createOffer();
  await peerConnection.setLocalDescription(offer);

  socket.emit('offer', { sdp: offer, room });
};

hangupBtn.onclick = () => {
  if (peerConnection) peerConnection.close();
  peerConnection = null;
  remoteVideo.srcObject = null;

  if (localStream) {
    localStream.getTracks().forEach(track => track.stop());
    localVideo.srcObject = null;
  }

  startCallBtn.disabled = false;
  hangupBtn.disabled = true;

  socket.emit('leave', { room });
};

socket.on('connect', () => {
  socket.emit('join', { room });
});

socket.on('offer', async data => {
  if (!peerConnection) {
    await startLocalStream();
    createPeerConnection();
  }
  await peerConnection.setRemoteDescription(new RTCSessionDescription(data.sdp));

  const answer = await peerConnection.createAnswer();
  await peerConnection.setLocalDescription(answer);

  socket.emit('answer', { sdp: answer, room });
});

socket.on('answer', async data => {
  await peerConnection.setRemoteDescription(new RTCSessionDescription(data.sdp));
});

socket.on('ice-candidate', async data => {
  try {
    await peerConnection.addIceCandidate(new RTCIceCandidate(data.candidate));
  } catch (e) {
    console.error('Error adding received ice candidate', e);
  }
});

socket.on('leave', () => {
  if (peerConnection) {
    peerConnection.close();
    peerConnection = null;
    remoteVideo.srcObject = null;
  }
  if (localStream) {
    localStream.getTracks().forEach(track => track.stop());
    localVideo.srcObject = null;
  }
  startCallBtn.disabled = false;
  hangupBtn.disabled = true;
});