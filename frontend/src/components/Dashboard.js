import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { 
  Container, 
  Button, 
  Typography, 
  Box,
  Paper,
  Grid,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  FormControlLabel,
  Switch,
  List,
  ListItem,
  ListItemText,
  IconButton,
  TextField
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import ElectionsList from './ElectionsList';
import DeleteIcon from '@mui/icons-material/Delete';
import AddIcon from '@mui/icons-material/Add';
import AdminElectionsList from './AdminElectionsList';

function Dashboard() {
  const { logout, user } = useAuth();
  const navigate = useNavigate();
  const [invitationCode, setInvitationCode] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [openDialog, setOpenDialog] = useState(false);
  const [useEC, setUseEC] = useState(true);
  const [candidates, setCandidates] = useState([{ name: '' }, { name: '' }]);
  const [electionName, setElectionName] = useState('');

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const generateInvitationCode = async () => {
    try {
      const response = await api.post('/auth/generate-invitation');
      setInvitationCode(response.data.code);
      setSuccess('Code d\'invitation généré avec succès');
      setError('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Erreur lors de la génération du code');
      setSuccess('');
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
    } catch (err) {
      setError(err.response?.data?.detail || 'Erreur lors de l\'initialisation de l\'élection');
    }
  };

  return (
    <Container>
      <Box sx={{ mt: 4 }}>
        <Typography variant="h4" gutterBottom>
          Dashboard
        </Typography>

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

        <Grid container spacing={3}>
          {user?.is_admin ? (
            <>
              <Grid item xs={12}>
                <Paper sx={{ p: 3 }}>
                  <Typography variant="h6" gutterBottom>
                    Gestion des invitations
                  </Typography>
                  <Button 
                    variant="contained" 
                    color="primary" 
                    onClick={generateInvitationCode}
                    sx={{ mb: 2 }}
                  >
                    Générer un code d'invitation
                  </Button>
                  {invitationCode && (
                    <Box sx={{ mt: 2, p: 2, bgcolor: 'background.paper', borderRadius: 1 }}>
                      <Typography variant="body1">
                        Code d'invitation : <code>{invitationCode}</code>
                      </Typography>
                    </Box>
                  )}
                </Paper>
              </Grid>

              <Grid item xs={12}>
                <AdminElectionsList />
              </Grid>
            </>
          ) : (
            <Grid item xs={12}>
              <ElectionsList />
            </Grid>
          )}

          <Grid item xs={12}>
            <Button 
              variant="contained" 
              color="secondary" 
              onClick={handleLogout}
              sx={{ mt: 2 }}
            >
              Se déconnecter
            </Button>
          </Grid>
        </Grid>

        <Dialog open={openDialog} onClose={() => setOpenDialog(false)} maxWidth="sm" fullWidth>
          <DialogTitle>Initialiser une nouvelle élection</DialogTitle>
          <DialogContent>
            <DialogContentText>
              Configurez les paramètres de l'élection.
            </DialogContentText>
            
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

            <TextField
              fullWidth
              label="Nom de l'élection"
              value={electionName}
              onChange={(e) => setElectionName(e.target.value)}
              margin="normal"
              required
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setOpenDialog(false)}>Annuler</Button>
            <Button onClick={initializeElection} variant="contained" color="primary">
              Initialiser
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </Container>
  );
}

export default Dashboard; 