import { lazy, Suspense } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ApiError } from './api/client';
import { useLang } from './i18n';
import { RequireSession } from './session';
import { Layout } from './shell/Layout';
import { SkeletonRows, Toaster } from './ui/kit';
import Login from './pages/Login';

const Dashboard = lazy(() => import('./pages/Dashboard'));
const Runs = lazy(() => import('./pages/Runs'));
const RunDetail = lazy(() => import('./pages/RunDetail'));
const Hosts = lazy(() => import('./pages/Hosts'));
const HostDetail = lazy(() => import('./pages/HostDetail'));
const Services = lazy(() => import('./pages/Services'));
const ServiceDetail = lazy(() => import('./pages/ServiceDetail'));
const Changes = lazy(() => import('./pages/Changes'));
const Compare = lazy(() => import('./pages/Compare'));
const Findings = lazy(() => import('./pages/Findings'));
const Signatures = lazy(() => import('./pages/Signatures'));
const SignatureEditor = lazy(() => import('./pages/SignatureEditor'));
const Targets = lazy(() => import('./pages/Targets'));
const Profiles = lazy(() => import('./pages/Profiles'));
const ProfileEdit = lazy(() => import('./pages/ProfileEdit'));
const Transfer = lazy(() => import('./pages/Transfer'));
const Admin = lazy(() => import('./pages/Admin'));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      refetchOnWindowFocus: false,
      // A 4xx answer and a 501 (module not connected) do not change on a second try.
      retry: (count, err) => !(err instanceof ApiError && ((err.status >= 400 && err.status < 500) || err.status === 501)) && count < 2,
    },
  },
});

function Shell() {
  return (
    <RequireSession>
      <Layout />
    </RequireSession>
  );
}

export default function App() {
  // Subscribing here re-renders the whole tree when the language changes.
  const lang = useLang();
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Suspense fallback={<SkeletonRows rows={10} />}>
          <Routes key={lang}>
            <Route path="/login" element={<Login />} />
            <Route element={<Shell />}>
              <Route index element={<Suspense fallback={<SkeletonRows rows={10} />}><Dashboard /></Suspense>} />
              <Route path="runs" element={<Runs />} />
              <Route path="runs/:id" element={<RunDetail />} />
              <Route path="hosts" element={<Hosts />} />
              <Route path="hosts/:id" element={<HostDetail />} />
              <Route path="services" element={<Services />} />
              <Route path="services/:id" element={<ServiceDetail />} />
              <Route path="changes" element={<Changes />} />
              <Route path="changes/compare" element={<Compare />} />
              <Route path="findings" element={<Findings />} />
              <Route path="signatures" element={<Signatures />} />
              <Route path="signatures/new" element={<SignatureEditor />} />
              <Route path="signatures/:id" element={<SignatureEditor />} />
              <Route path="targets" element={<Targets />} />
              <Route path="profiles" element={<Profiles />} />
              <Route path="profiles/new" element={<ProfileEdit />} />
              <Route path="profiles/:id" element={<ProfileEdit />} />
              <Route path="transfer" element={<Transfer />} />
              <Route path="admin" element={<Admin />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </Suspense>
        <Toaster />
      </BrowserRouter>
    </QueryClientProvider>
  );
}
