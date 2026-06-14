import { motion } from 'framer-motion'
import type { ReactNode } from 'react'

interface Props {
  id?: string
  children: ReactNode
  className?: string
}

export default function ScrollSection({ id, children, className = '' }: Props) {
  return (
    <motion.section
      id={id}
      className={`section ${className}`}
      initial={{ opacity: 0, y: 60 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.7, ease: [0.25, 0.1, 0.25, 1] }}
      viewport={{ once: true, margin: '-100px' }}
    >
      {children}
      <div className="glow-divider" />
    </motion.section>
  )
}
