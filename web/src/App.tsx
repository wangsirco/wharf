import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from '@/lib/auth'
import { useBrand } from '@/lib/brand'
import { Welcome } from '@/components/welcome'
import { Toaster } from '@/components/ui/sonner'
import { Layout, SimpleLayout } from '@/components/layout'
import { ModeProvider, useMode } from '@/lib/mode'
import { SimpleHome, SimpleDevicePage } from '@/pages/simple'
import Login from '@/pages/login'
import Dashboard from '@/pages/dashboard'
import Devices from '@/pages/devices'
import Users from '@/pages/users'
import Audit from '@/pages/audit'
import Approvals from '@/pages/approvals'
import Requests from '@/pages/requests'
import Visitors from '@/pages/visitors'
import SettingsPage from '@/pages/settings'
import Account from '@/pages/account'
import Forwards from '@/pages/forwards'
import Access from '@/pages/access'
import DevicePage from '@/pages/device'
import Traffic from '@/pages/traffic'
import Controls from '@/pages/controls'
import DNS from '@/pages/dns'
import Screen from '@/pages/screen'
import Network from '@/pages/network'
import World from '@/pages/world'
import Alerts from '@/pages/alerts'
import SystemPage from '@/pages/system'
import Tools from '@/pages/tools'

function Home() {
  const { can } = useAuth()
  if (can('dashboard.view')) return <Dashboard />
  if (can('devices.view')) return <Navigate to="/devices" replace />
  return <Navigate to="/requests" replace />
}

function Routed() {
  const { user, loading, isSuper } = useAuth()
  const { mode } = useMode()
  if (loading) return null
  if (!user) return <Login />
  const superOnly = (el: React.ReactElement) => (isSuper ? el : <Navigate to="/" replace />)
  if (mode === 'simple') {
    return (
      <Routes>
        <Route path="screen" element={<Screen />} />
        <Route element={<SimpleLayout />}>
          <Route index element={<SimpleHome />} />
          <Route path="devices/:mac" element={<SimpleDevicePage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    )
  }
  return (
    <Routes>
      <Route path="screen" element={<Screen />} />
      <Route element={<Layout />}>
        <Route index element={<Home />} />
        <Route path="devices" element={<Devices />} />
        <Route path="devices/:mac" element={<DevicePage />} />
        <Route path="traffic" element={<Traffic />} />
        <Route path="controls" element={<Controls />} />
        <Route path="dns" element={<DNS />} />
        <Route path="network" element={<Network />} />
        <Route path="world" element={<World />} />
        <Route path="alerts" element={superOnly(<Alerts />)} />
        <Route path="system" element={<SystemPage />} />
        <Route path="tools" element={<Tools />} />
        <Route path="requests" element={<Requests />} />
        <Route path="forwards" element={<Forwards />} />
        <Route path="access" element={superOnly(<Access />)} />
        <Route path="account" element={<Account />} />
        <Route path="users" element={superOnly(<Users />)} />
        <Route path="approvals" element={superOnly(<Approvals />)} />
        <Route path="audit" element={superOnly(<Audit />)} />
        <Route path="visitors" element={superOnly(<Visitors />)} />
        <Route path="settings" element={superOnly(<SettingsPage />)} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}

export default function App() {
  useBrand() // keeps the browser tab title in sync with the custom panel name
  return (
    <BrowserRouter>
      <AuthProvider>
        <ModeProvider>
          <Routed />
          <Welcome />
        </ModeProvider>
        <Toaster position="top-center" richColors />
      </AuthProvider>
    </BrowserRouter>
  )
}
