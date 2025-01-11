import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Paper,
  Typography,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Button,
  Chip,
  Box,
  Alert,
} from '@mui/material';
import { api } from '../services/api';

function ElectionsList() {
  const navigate = useNavigate();
  const [elections, setElections] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchElections();
  }, []);

  const fetchElections = async () => {
    try {
      const response = await api.get('/elections');
      setElections(response.data);
      setError('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Erreur lors du chargement des élections');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'ongoing':
        return 'primary';
      case 'completed':
        return 'success';
      default:
        return 'default';
    }
  };

  const getStatusLabel = (status) => {
    switch (status) {
      case 'ongoing':
        return 'En cours';
      case 'completed':
        return 'Terminée';
      default:
        return status;
    }
  };

  if (loading) {
    return <Typography>Chargement...</Typography>;
  }

  return (
    <Paper sx={{ p: 3, mt: 3 }}>
      <Typography variant="h6" gutterBottom>
        Élections disponibles
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {elections.length === 0 ? (
        <Typography color="textSecondary">
          Aucune élection disponible pour le moment.
        </Typography>
      ) : (
        <List>
          {elections.map((election) => (
            <ListItem
              key={election.id}
              divider
              sx={{
                '&:hover': {
                  backgroundColor: 'action.hover',
                },
              }}
            >
              <ListItemText
                primary={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                    <Typography variant="subtitle1">
                      Élection #{election.id}
                    </Typography>
                    <Chip
                      size="small"
                      label={getStatusLabel(election.status)}
                      color={getStatusColor(election.status)}
                    />
                  </Box>
                }
                secondary={
                  <>
                    <Typography variant="body2" component="span">
                      Créée le {formatDate(election.created_at)}
                    </Typography>
                    <br />
                    <Typography variant="body2" component="span">
                      {election.total_votes} votes enregistrés • {election.remaining_votes} votes restants
                    </Typography>
                  </>
                }
              />
              <ListItemSecondaryAction>
                <Button
                  variant="outlined"
                  color="primary"
                  onClick={() => navigate(`/election/${election.id}`)}
                >
                  Participer
                </Button>
              </ListItemSecondaryAction>
            </ListItem>
          ))}
        </List>
      )}
    </Paper>
  );
}

export default ElectionsList; 