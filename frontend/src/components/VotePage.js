import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Container,
  Paper,
  Typography,
  RadioGroup,
  FormControlLabel,
  Radio,
  Button,
  Box,
  Alert,
} from '@mui/material';
import { api } from '../services/api';

function VotePage() {
  const { electionId } = useParams();
  const navigate = useNavigate();
  const [candidates, setCandidates] = useState([]);
  const [selectedCandidate, setSelectedCandidate] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchCandidates();
  }, [electionId]);

  const fetchCandidates = async () => {
    try {
      const response = await api.get(`/election/${electionId}/candidates`);
      setCandidates(response.data);
      setError('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Erreur lors du chargement des candidats');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!selectedCandidate) {
      setError('Veuillez sélectionner un candidat');
      return;
    }

    try {
      await api.post(`/vote`, {
        election_id: parseInt(electionId),
        candidate: parseInt(selectedCandidate)
      });
      setSuccess('Vote enregistré avec succès');
      setError('');
      // Redirection après quelques secondes
      setTimeout(() => navigate('/'), 2000);
    } catch (err) {
      setError(err.response?.data?.detail || 'Erreur lors de l\'enregistrement du vote');
    }
  };

  if (loading) {
    return <Typography>Chargement...</Typography>;
  }

  return (
    <Container maxWidth="sm">
      <Box sx={{ mt: 4 }}>
        <Paper sx={{ p: 3 }}>
          <Typography variant="h5" gutterBottom>
            Voter - Élection #{electionId}
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

          <form onSubmit={handleSubmit}>
            <RadioGroup
              value={selectedCandidate}
              onChange={(e) => setSelectedCandidate(e.target.value)}
            >
              {candidates.map((candidate) => (
                <FormControlLabel
                  key={candidate.id}
                  value={candidate.id.toString()}
                  control={<Radio />}
                  label={candidate.name}
                />
              ))}
            </RadioGroup>

            <Box sx={{ mt: 3, display: 'flex', gap: 2 }}>
              <Button
                type="button"
                variant="outlined"
                onClick={() => navigate('/')}
              >
                Retour
              </Button>
              <Button
                type="submit"
                variant="contained"
                color="primary"
                disabled={!selectedCandidate}
              >
                Voter
              </Button>
            </Box>
          </form>
        </Paper>
      </Box>
    </Container>
  );
}

export default VotePage; 