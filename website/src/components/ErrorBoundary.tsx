import { Component, ReactNode } from 'react'

interface Props {
  children: ReactNode
  /** Optional fallback node shown in place of the children when they error. */
  fallback?: ReactNode
  /** Optional tag used in the console warning so operators can tell different boundaries apart. */
  scope?: string
}

interface State {
  hasError: boolean
}

/**
 * Class-based React error boundary. Mainly exists to contain WebGL / Three.js
 * failures in the 3D scene so a driver glitch doesn't crash the whole page.
 *
 * Errors are logged to the console (not reported anywhere — we deliberately
 * don't ship an analytics SDK). In production, `fallback` should be a silent
 * `null` so the page renders normally without the broken sub-tree.
 */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false }

  static getDerivedStateFromError(): State {
    return { hasError: true }
  }

  componentDidCatch(error: Error, info: { componentStack: string }): void {
    const scope = this.props.scope ?? 'app'
    // eslint-disable-next-line no-console
    console.warn(`[ErrorBoundary:${scope}] contained an error:`, error, info.componentStack)
  }

  render(): ReactNode {
    if (this.state.hasError) {
      return this.props.fallback ?? null
    }
    return this.props.children
  }
}
