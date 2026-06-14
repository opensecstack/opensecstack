import { useState } from 'react'

interface CodeBlockProps {
  code: string
  language: 'go' | 'typescript' | 'bash' | 'yaml'
  filename?: string
}

function highlightGo(code: string): string {
  const keywords = ['func', 'import', 'package', 'var', 'const', 'type', 'struct', 'return', 'if', 'err', 'nil', 'true', 'false', 'range', 'for', 'switch', 'case', 'break', 'continue', 'defer', 'go', 'chan', 'select', 'map', 'interface']
  let result = escapeHtml(code)

  // Comments
  result = result.replace(/(\/\/[^\n]*)/g, '<span class="cm">$1</span>')

  // Strings
  result = result.replace(/("(?:[^"\\]|\\.)*")/g, '<span class="str">$1</span>')
  result = result.replace(/(`[^`]*`)/g, '<span class="str">$1</span>')

  // Keywords (only whole words, not inside strings/comments)
  const kwPattern = new RegExp(`\\b(${keywords.join('|')})\\b`, 'g')
  result = result.replace(kwPattern, (match) => `<span class="kw">${match}</span>`)

  // Function calls
  result = result.replace(/\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g, '<span class="fn">$1</span>(')

  return result
}

function highlightTypeScript(code: string): string {
  const keywords = ['const', 'let', 'var', 'async', 'await', 'import', 'export', 'function', 'return', 'if', 'else', 'new', 'true', 'false', 'null', 'undefined', 'from', 'class', 'extends', 'interface', 'type', 'for', 'of', 'in']
  let result = escapeHtml(code)

  // Comments
  result = result.replace(/(\/\/[^\n]*)/g, '<span class="cm">$1</span>')

  // Strings (single, double, template)
  result = result.replace(/('(?:[^'\\]|\\.)*')/g, '<span class="str">$1</span>')
  result = result.replace(/("(?:[^"\\]|\\.)*")/g, '<span class="str">$1</span>')
  result = result.replace(/(`[^`]*`)/g, '<span class="str">$1</span>')

  // Keywords
  const kwPattern = new RegExp(`\\b(${keywords.join('|')})\\b`, 'g')
  result = result.replace(kwPattern, (match) => `<span class="kw">${match}</span>`)

  // Function calls
  result = result.replace(/\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g, '<span class="fn">$1</span>(')

  return result
}

function highlightBash(code: string): string {
  let result = escapeHtml(code)

  // Comments
  result = result.replace(/(#[^\n]*)/g, '<span class="cm">$1</span>')

  // Strings
  result = result.replace(/("(?:[^"\\]|\\.)*")/g, '<span class="str">$1</span>')
  result = result.replace(/('(?:[^'\\]|\\.)*')/g, '<span class="str">$1</span>')

  // $ variables
  result = result.replace(/(\$[a-zA-Z_][a-zA-Z0-9_]*|\$\{[^}]+\})/g, '<span class="dollar">$1</span>')

  return result
}

function highlightYaml(code: string): string {
  let result = escapeHtml(code)

  // Comments
  result = result.replace(/(#[^\n]*)/g, '<span class="cm">$1</span>')

  // Keys (word followed by colon)
  result = result.replace(/^(\s*)([a-zA-Z_][a-zA-Z0-9_-]*)(\s*:)/gm, '$1<span class="key">$2</span>$3')

  // Values that are strings (after colon)
  result = result.replace(/:\s+([^\n{[#]+)/g, ': <span class="str">$1</span>')

  // Numbers
  result = result.replace(/:\s+(\d+)/g, ': <span class="num">$1</span>')

  return result
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function highlight(code: string, language: 'go' | 'typescript' | 'bash' | 'yaml'): string {
  switch (language) {
    case 'go': return highlightGo(code)
    case 'typescript': return highlightTypeScript(code)
    case 'bash': return highlightBash(code)
    case 'yaml': return highlightYaml(code)
  }
}

const LANG_LABELS: Record<string, string> = {
  go: 'Go',
  typescript: 'TypeScript',
  bash: 'Bash',
  yaml: 'YAML',
}

export default function CodeBlock({ code, language, filename }: CodeBlockProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const highlighted = highlight(code.trim(), language)

  return (
    <div className="code-block-wrapper">
      <div className="code-block-header">
        <span className="code-block-filename">
          {filename ? filename : <span className="code-block-lang">{LANG_LABELS[language]}</span>}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {filename && <span className="code-block-lang">{LANG_LABELS[language]}</span>}
          <button
            className={`code-block-copy ${copied ? 'copied' : ''}`}
            onClick={handleCopy}
          >
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </div>
      </div>
      <pre
        className="code-block-pre"
        dangerouslySetInnerHTML={{ __html: highlighted }}
      />
    </div>
  )
}
