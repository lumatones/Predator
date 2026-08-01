import { Routes, Route, useLocation } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import Navbar from './components/Navbar'
import Footer from './components/Footer'
import Hero from './pages/Hero'
import PlayersDB from './pages/PlayersDB'
import News from './pages/News'
import Profile from './pages/Profile'
import Login from './pages/Login'

export default function App() {
  const location = useLocation()

  return (
    <div className="min-h-screen flex flex-col scan-line-overlay grid-bg">
      <Navbar />
      <main className="flex-1">
        <AnimatePresence mode="wait">
          <Routes location={location} key={location.pathname}>
            <Route path="/" element={<Hero />} />
            <Route path="/players" element={<PlayersDB />} />
            <Route path="/news" element={<News />} />
            <Route path="/profile" element={<Profile />} />
            <Route path="/login" element={<Login />} />
          </Routes>
        </AnimatePresence>
      </main>
      <Footer />
    </div>
  )
}
