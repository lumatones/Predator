/**
 * Predator — Mini Player Bar
 *
 * Floating bottom bar that appears when music is playing.
 * Shows current track info + basic controls without opening the full player.
 *
 * Always visible on main/checker/dashboard phases.
 */

import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useMusicPlayerContext } from '../../hooks/useMusicPlayer'

interface MiniPlayerProps {
  onOpenFull: () => void
  accent: string
}

export const MiniPlayer: React.FC<MiniPlayerProps> = ({ onOpenFull, accent }) => {
  const {
    currentTrack, status, currentTime, duration,
    togglePlayPause, handleNext,
  } = useMusicPlayerContext()

  if (!currentTrack) return null

  const progress = duration > 0 ? (currentTime / duration) * 100 : 0

  return (
    <AnimatePresence>
      {currentTrack && (
        <motion.div
          className="mini-player"
          style={{ '--mini-accent': accent } as React.CSSProperties}
          initial={{ y: 80, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: 80, opacity: 0 }}
          transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
        >
          {/* Progress bar */}
          <div className="mini-player-progress" style={{ width: `${progress}%` }} />

          {/* Cover + Info */}
          <div className="mini-player-left" onClick={onOpenFull}>
            {currentTrack.coverUrl ? (
              <img className="mini-player-cover" src={currentTrack.coverUrl} alt="" />
            ) : (
              <div className="mini-player-cover mini-player-cover--placeholder">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M9 18V5l12-2v13" /><circle cx="6" cy="18" r="3" /><circle cx="18" cy="16" r="3" />
                </svg>
              </div>
            )}
            <div className="mini-player-info">
              <span className="mini-player-title">{currentTrack.title}</span>
              <span className="mini-player-artist">{currentTrack.artist}</span>
            </div>
          </div>

          {/* Controls */}
          <div className="mini-player-controls">
            <button
              className="mini-player-btn"
              onClick={togglePlayPause}
              aria-label={status === 'playing' ? 'Pause' : 'Play'}
            >
              {status === 'playing' ? (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                  <rect x="6" y="4" width="4" height="16" rx="1" />
                  <rect x="14" y="4" width="4" height="16" rx="1" />
                </svg>
              ) : (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                  <polygon points="5 3 19 12 5 21 5 3" />
                </svg>
              )}
            </button>
            <button className="mini-player-btn" onClick={handleNext} aria-label="Next">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polygon points="5 4 15 12 5 20 5 4" /><line x1="19" y1="5" x2="19" y2="19" />
              </svg>
            </button>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
