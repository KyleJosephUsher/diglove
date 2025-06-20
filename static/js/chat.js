const socket = io();

// Get elements
const chatForm = document.getElementById('chatForm');
const chatInput = document.getElementById('chatInput');
const messagesContainer = document.getElementById('messages');
const room = CHAT_ROOM; // Injected from template, e.g. "{{ room_id }}"

// Join the room
socket.emit('join', { room });

// Listen for messages from server
socket.on('message', data => {
  appendMessage(data);
});

// Append message to chat container
function appendMessage({ sender, message, timestamp }) {
  const messageElement = document.createElement('div');
  messageElement.classList.add('message');

  const time = new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  messageElement.innerHTML = `
    <strong>${sender}:</strong> ${escapeHtml(message)} <span class="text-muted" style="font-size: 0.8em;">${time}</span>
  `;

  messagesContainer.appendChild(messageElement);
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Handle form submit
chatForm.addEventListener('submit', e => {
  e.preventDefault();

  const message = chatInput.value.trim();
  if (message === '') return;

  // Emit message to server
  socket.emit('send_message', { room, message });

  // Optionally show own message instantly
  appendMessage({ sender: 'You', message, timestamp: Date.now() });

  chatInput.value = '';
  chatInput.focus();
});
