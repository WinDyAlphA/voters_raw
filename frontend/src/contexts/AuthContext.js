import React, { createContext, useContext, useState } from 'react';
import { api } from '../services/api';
import { jwtDecode } from 'jwt-decode';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [user, setUser] = useState(() => {
    const savedToken = localStorage.getItem('token');
    if (savedToken) {
      try {
        const decoded = jwtDecode(savedToken);
        return { username: decoded.sub, is_admin: decoded.is_admin };
      } catch (e) {
        return null;
      }
    }
    return null;
  });

  const login = async (username, password) => {
    const response = await api.post('/auth/login', { username, password });
    const newToken = response.data.access_token;
    localStorage.setItem('token', newToken);
    setToken(newToken);
    
    // Décode le token pour obtenir les informations utilisateur
    const decoded = jwtDecode(newToken);
    setUser({ username: decoded.sub, is_admin: decoded.is_admin });
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ token, user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}; 