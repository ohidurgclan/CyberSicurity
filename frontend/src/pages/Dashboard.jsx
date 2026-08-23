import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

const getStoredUser = () => {
  const stored = localStorage.getItem('user');
  return stored ? JSON.parse(stored) : null;
}

const Dashboard = () => {
  const [user] = useState(getStoredUser);
  const navigate = useNavigate();

  useEffect(() => {
    if (!user) navigate('/login');
  }, [user, navigate]);

  const handleLogout = () => {
    localStorage.removeItem('user');
    navigate('/login');
  }

  if (!user) return null;

  return (
    <div className="dashboard-page">
      <nav className="dashboard-nav">
        <span className="dashboard-brand">SecureAuth With AES-256</span>
        <button className="logout-btn" onClick={handleLogout}>
          Log out
        </button>
      </nav>

      <main className="dashboard-content">
        <span className="dashboard-eyebrow">Signed in</span>
        <h1>Welcome to dashboard {user.name}</h1>
        <p>You're logged in as {user.email}</p>

        <div className="status-grid">
          <div className="status-card">
            <div className="status-card-label">Password storage</div>
            <div className="status-card-value">
              <span className="status-dot" />
              AES-256, encrypted
            </div>
          </div>
          <div className="status-card">
            <div className="status-card-label">Session</div>
            <div className="status-card-value">
              <span className="status-dot" />
              Active
            </div>
          </div>
        </div>
      </main>
      <footer className="dashboard-footer">
        <span>© {new Date().getFullYear()} SecureAuth With AES-256 All rights reserved.</span>
        <span>Developed by Md Ohidur Rahman </span>
      </footer>
    </div>
  );
}

export default Dashboard;
