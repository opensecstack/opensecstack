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
      initial={{ opacity: 0, y: 40 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, ease: 'easeOut' }}
      viewport={{ once: true, margin: '-80px' }}
    >
      {children}
    </motion.section>
  )
}
