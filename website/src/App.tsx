import { Routes, Route, useLocation } from 'react-router-dom'
import { AnimatePresence, motion, useReducedMotion, useScroll, useTransform } from 'framer-motion'
import Navbar from './components/Navbar'
import Footer from './components/Footer'
import Hero from './pages/Hero'
import PlayersDB from './pages/PlayersDB'
import News from './pages/News'
import Profile from './pages/Profile'
import Login from './pages/Login'

function AmbientBackground() {
  const { scrollY } = useScroll()
  const reduceMotion = useReducedMotion()
  const motionDisabled = reduceMotion !== false
  const firstY = useTransform(scrollY, [0, 1200], [0, 150])
  const secondY = useTransform(scrollY, [0, 1200], [0, -100])
  const thirdY = useTransform(scrollY, [0, 1200], [0, 70])

  return (
    <div className="ambient-background" aria-hidden="true">
      <motion.div className="ambient-parallax" style={motionDisabled ? undefined : { y: firstY }}><div className="ambient-blob ambient-blob--blue" /></motion.div>
      <motion.div className="ambient-parallax" style={motionDisabled ? undefined : { y: secondY }}><div className="ambient-blob ambient-blob--violet" /></motion.div>
      <motion.div className="ambient-parallax" style={motionDisabled ? undefined : { y: thirdY }}><div className="ambient-blob ambient-blob--white" /></motion.div>
      <div className="ambient-grain" />
    </div>
  )
}

export default function App() {
  const location = useLocation()
  const reduceMotion = useReducedMotion()
  const motionDisabled = reduceMotion !== false

  return (
    <div className="relative min-h-screen overflow-x-clip bg-predator-bg text-predator-text">
      <AmbientBackground />
      <Navbar />
      <main className="relative z-10">
        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={location.pathname}
            initial={motionDisabled ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={motionDisabled ? undefined : { opacity: 0 }}
            transition={motionDisabled ? undefined : { duration: 0.34, ease: [0.16, 1, 0.3, 1] }}
          >
            <Routes location={location}>
              <Route path="/" element={<Hero />} />
              <Route path="/players" element={<PlayersDB />} />
              <Route path="/news" element={<News />} />
              <Route path="/profile" element={<Profile />} />
              <Route path="/login" element={<Login />} />
            </Routes>
          </motion.div>
        </AnimatePresence>
      </main>
      <div className="relative z-10">
        <Footer />
      </div>
    </div>
  )
}
