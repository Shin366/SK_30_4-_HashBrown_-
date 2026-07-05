import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { AnalysisProvider } from '@/context/AnalysisContext';
import './index.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AnalysisProvider>
      <App />
    </AnalysisProvider>
  </StrictMode>,
);
