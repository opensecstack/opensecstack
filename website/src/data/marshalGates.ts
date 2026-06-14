export interface MarshalGate {
  number: number
  name: string
  description: string
}

export const marshalGates: MarshalGate[] = [
  { number: 1, name: 'Authority',    description: 'Validates the request originates from an authorised actor with valid credentials.' },
  { number: 2, name: 'Scope',        description: 'Ensures the requested action falls within the actor\'s permitted scope.' },
  { number: 3, name: 'Determinism',  description: 'Verifies the outcome is deterministic and reproducible.' },
  { number: 4, name: 'Evidence',     description: 'Collects and validates supporting evidence before execution.' },
  { number: 5, name: 'Schema',       description: 'Validates the payload against the expected structural schema.' },
]
