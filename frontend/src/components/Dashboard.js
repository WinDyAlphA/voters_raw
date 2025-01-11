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
  Switch
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import ElectionsList from './ElectionsList';

function Dashboard() {
  const { logout, user } = useAuth();
  const navigate = useNavigate();
  const [invitationCode, setInvitationCode] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [openDialog, setOpenDialog] = useState(false);
  const [useEC, setUseEC] = useState(true);

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

  const initializeElection = async () => {
    try {
      await api.post('/election/init', { use_ec: useEC });
      setSuccess('Élection initialisée avec succès');
      setError('');
      setOpenDialog(false);
    } catch (err) {
      setError(err.response?.data?.detail || 'Erreur lors de l\'initialisation de l\'élection');
      setSuccess('');
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
                <Paper sx={{ p: 3 }}>
                  <Typography variant="h6" gutterBottom>
                    Gestion des élections
                  </Typography>
                  <Button 
                    variant="contained" 
                    color="primary" 
                    onClick={() => setOpenDialog(true)}
                  >
                    Initialiser une nouvelle élection
                  </Button>
                </Paper>
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

        <Dialog open={openDialog} onClose={() => setOpenDialog(false)}>
          <DialogTitle>Initialiser une nouvelle élection</DialogTitle>
          <DialogContent>
            <DialogContentText>
              Choisissez le type de chiffrement pour l'élection.
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