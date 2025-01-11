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

  const handleVote = async (candidateId) => {
    try {
      const voteData = {
        election_id: electionId,
        candidate: candidateId
      };

      const response = await api.post('/vote', voteData);
      
      if (response.status === 200) {
        setSuccess('Vote enregistré avec succès');
        navigate('/elections');
      }
    } catch (error) {
      console.error('Erreur lors du vote:', error);
      setError('Erreur lors de l\'enregistrement du vote');
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

          <form onSubmit={() => handleVote(selectedCandidate)}>
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