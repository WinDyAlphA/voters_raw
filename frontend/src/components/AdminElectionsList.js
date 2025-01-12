import React, { useState, useEffect } from 'react';
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
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControlLabel,
  Switch,
  IconButton,
  DialogContentText,
} from '@mui/material';
import { api } from '../services/api';
import DeleteIcon from '@mui/icons-material/Delete';
import AddIcon from '@mui/icons-material/Add';

function AdminElectionsList() {
  const [elections, setElections] = useState([]);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(true);
  const [selectedElection, setSelectedElection] = useState(null);
  const [results, setResults] = useState(null);
  const [openDialog, setOpenDialog] = useState(false);
  const [useEC, setUseEC] = useState(true);
  const [candidates, setCandidates] = useState([{ name: '' }, { name: '' }]);
  const [electionName, setElectionName] = useState('');

  useEffect(() => {
    fetchElections();
  }, []);

  const fetchElections = async () => {
    try {
      const response = await api.get('/admin/elections');
      setElections(response.data);
      setError('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Erreur lors du chargement des élections');
    } finally {
      setLoading(false);
    }
  };

  const closeElection = async (electionId) => {
    try {
      await api.post(`/election/${electionId}/close`);
      setSuccess('Élection fermée avec succès');
      fetchElections();
    } catch (err) {
      setError(err.response?.data?.detail || 'Erreur lors de la fermeture de l\'élection');
    }
  };

  const viewResults = async (election) => {
    try {
      setError('');
      const response = await api.get(`/election/${election.id}/results`);
      if (response.data) {
        setResults(response.data);
        setSelectedElection(election);
      } else {
        setError('Aucun résultat disponible');
      }
    } catch (err) {
      console.error('Erreur lors de la récupération des résultats:', err);
      setError(err.response?.data?.detail || 'Erreur lors de la récupération des résultats');
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  const initializeElection = async () => {
    try {
      if (!electionName.trim()) {
        setError('Le nom de l\'élection est requis');
        return;
      }
      if (candidates.some(c => !c.name.trim())) {
        setError('Tous les candidats doivent avoir un nom');
        return;
      }

      await api.post('/election/init', {
        name: electionName,
        use_ec: useEC,
        candidates: candidates
      });
      setSuccess('Élection initialisée avec succès');
      setError('');
      setOpenDialog(false);
      setElectionName('');
      setCandidates([{ name: '' }, { name: '' }]);
      fetchElections();
    } catch (err) {
      setError(err.response?.data?.detail || 'Erreur lors de l\'initialisation de l\'élection');
    }
  };

  const addCandidate = () => {
    if (candidates.length < 20) {
      setCandidates([...candidates, { name: '' }]);
    }
  };

  const removeCandidate = (index) => {
    if (candidates.length > 2) {
      const newCandidates = candidates.filter((_, i) => i !== index);
      setCandidates(newCandidates);
    }
  };

  const updateCandidate = (index, name) => {
    const newCandidates = [...candidates];
    newCandidates[index].name = name;
    setCandidates(newCandidates);
  };

  if (loading) {
    return <Typography>Chargement...</Typography>;
  }

  return (
    <Paper sx={{ p: 3, mt: 3 }}>
      <Typography variant="h6" gutterBottom>
        Gestion des élections
      </Typography>

      <Button 
        variant="contained" 
        color="primary" 
        onClick={() => setOpenDialog(true)}
        sx={{ mb: 2 }}
      >
        Nouvelle élection
      </Button>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {success}
        </Alert>
      )}

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
                    {election.name}
                  </Typography>
                  <Chip
                    size="small"
                    label={election.status === 'ongoing' ? 'En cours' : 'Terminée'}
                    color={election.status === 'ongoing' ? 'primary' : 'success'}
                  />
                </Box>
              }
              secondary={
                <>
                  <Typography variant="body2">
                    Créée le {formatDate(election.created_at)}
                  </Typography>
                  <Typography variant="body2">
                    {election.total_votes} votes enregistrés
                  </Typography>
                </>
              }
            />
            <ListItemSecondaryAction sx={{ display: 'flex', gap: 1 }}>
              {election.status === 'ongoing' && (
                <Button
                  variant="outlined"
                  color="warning"
                  onClick={() => closeElection(election.id)}
                >
                  Fermer
                </Button>
              )}
              {election.status === 'completed' && (
                <Button
                  variant="outlined"
                  color="primary"
                  onClick={() => viewResults(election)}
                >
                  Résultats
                </Button>
              )}
            </ListItemSecondaryAction>
          </ListItem>
        ))}
      </List>

      <Dialog 
        open={Boolean(selectedElection)} 
        onClose={() => {
          setSelectedElection(null);
          setResults(null);
          setError('');
        }}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          Résultats - {selectedElection?.name}
        </DialogTitle>
        <DialogContent>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}
          {results && results.candidates && (
            <List>
              {results.candidates.map((candidate, index) => (
                <ListItem key={candidate.id}>
                  <ListItemText
                    primary={candidate.name}
                    secondary={
                      `${results.results[index]} votes (${
                        results.total_votes > 0 
                          ? ((results.results[index] / results.total_votes) * 100).toFixed(1)
                          : 0
                      }%)`
                    }
                  />
                </ListItem>
              ))}
              <ListItem>
                <ListItemText
                  primary={`Total des votes : ${results.total_votes}`}
                />
              </ListItem>
            </List>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => {
            setSelectedElection(null);
            setResults(null);
            setError('');
          }}>
            Fermer
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={openDialog} onClose={() => setOpenDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Initialiser une nouvelle élection</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Configurez les paramètres de l'élection.
          </DialogContentText>
          
          <TextField
            fullWidth
            label="Nom de l'élection"
            value={electionName}
            onChange={(e) => setElectionName(e.target.value)}
            margin="normal"
            required
          />

          <FormControlLabel
            control={
              <Switch
                checked={useEC}
                onChange={(e) => setUseEC(e.target.checked)}
                color="primary"
              />
            }
            label={useEC ? "EC-ElGamal" : "ElGamal classique"}
          />

          <Typography variant="h6" sx={{ mt: 2, mb: 1 }}>
            Candidats
          </Typography>

          <List>
            {candidates.map((candidate, index) => (
              <ListItem
                key={index}
                secondaryAction={
                  candidates.length > 2 && (
                    <IconButton edge="end" onClick={() => removeCandidate(index)}>
                      <DeleteIcon />
                    </IconButton>
                  )
                }
              >
                <TextField
                  fullWidth
                  label={`Candidat ${index + 1}`}
                  value={candidate.name}
                  onChange={(e) => updateCandidate(index, e.target.value)}
                  size="small"
                  sx={{ mr: 1 }}
                />
              </ListItem>
            ))}
          </List>

          {candidates.length < 20 && (
            <Button
              startIcon={<AddIcon />}
              onClick={addCandidate}
              sx={{ mt: 1 }}
            >
              Ajouter un candidat
            </Button>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)}>Annuler</Button>
          <Button onClick={initializeElection} variant="contained" color="primary">
            Initialiser
          </Button>
        </DialogActions>
      </Dialog>
    </Paper>
  );
}

export default AdminElectionsList; 