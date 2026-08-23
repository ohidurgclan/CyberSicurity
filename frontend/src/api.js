const API_BASE = 'http://localhost:5000/api';

const request = async (path, body) => {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(data.error || 'Something went wrong. Please try again.');
  }

  return data;
}

export const signup = ({ name, email, password }) => {
  return request('/signup', { name, email, password });
}

export const login = ({ email, password }) => {
  return request('/login', { email, password });
}
