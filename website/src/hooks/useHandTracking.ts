import { useRef, useState, useCallback, useEffect } from 'react'

/**
 * Hand tracking data extracted each frame from MediaPipe.
 * All coordinates are normalized 0-1 (from webcam space).
 */
export interface HandState {
  active: boolean
  /** Center point of the hand (wrist landmark) — normalized [0-1, 0-1] */
  leftCenter: [number, number] | null
  rightCenter: [number, number] | null
  /** Distance between two hands (0-1 range), null if < 2 hands */
  handDistance: number | null
  /** Openness of left hand: 0 = fist, 1 = fully open */
  leftOpenness: number
  /** Openness of right hand: 0 = fist, 1 = fully open */
  rightOpenness: number
  /** Average center when two hands present */
  center: [number, number] | null
}

const INITIAL_STATE: HandState = {
  active: false,
  leftCenter: null,
  rightCenter: null,
  handDistance: null,
  leftOpenness: 0,
  rightOpenness: 0,
  center: null,
}

/**
 * Calculate hand openness from landmarks.
 * Compares fingertip-to-wrist distance vs palm width.
 * Returns 0 (fist) to 1 (open hand).
 */
function calcOpenness(landmarks: Array<{ x: number; y: number; z: number }>): number {
  // Wrist = 0, fingertips = 4 (thumb), 8 (index), 12 (middle), 16 (ring), 20 (pinky)
  const wrist = landmarks[0]
  const tips = [4, 8, 12, 16, 20]
  let totalDist = 0
  for (const idx of tips) {
    const tip = landmarks[idx]
    const dx = tip.x - wrist.x
    const dy = tip.y - wrist.y
    totalDist += Math.sqrt(dx * dx + dy * dy)
  }
  // Normalize: fist ~0.3, open hand ~0.9
  const avg = totalDist / tips.length
  return Math.min(1, Math.max(0, (avg - 0.05) / 0.25))
}

function distance2D(a: [number, number], b: [number, number]): number {
  const dx = a[0] - b[0]
  const dy = a[1] - b[1]
  return Math.sqrt(dx * dx + dy * dy)
}

export function useHandTracking() {
  const [enabled, setEnabled] = useState(false)
  const [state, setState] = useState<HandState>(INITIAL_STATE)
  const videoRef = useRef<HTMLVideoElement | null>(null)
  const detectorRef = useRef<any>(null)
  const rafRef = useRef<number>(0)
  const streamRef = useRef<MediaStream | null>(null)

  const start = useCallback(async () => {
    try {
      // Dynamic import to avoid loading the 5MB wasm at page load
      const { HandLandmarker, FilesetResolver } = await import('@mediapipe/tasks-vision')

      const filesetResolver = await FilesetResolver.forVisionTasks(
        'https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@latest/wasm'
      )

      const handLandmarker = await HandLandmarker.createFromOptions(filesetResolver, {
        baseOptions: {
          modelAssetPath: 'https://storage.googleapis.com/mediapipe-models/hand_landmarker/hand_landmarker/float16/1/hand_landmarker.task',
          delegate: 'GPU',
        },
        runningMode: 'VIDEO',
        numHands: 2,
        minHandDetectionConfidence: 0.5,
        minTrackingConfidence: 0.5,
      })

      detectorRef.current = handLandmarker

      // Start webcam
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { width: 640, height: 480, facingMode: 'user' },
      })
      streamRef.current = stream

      const video = document.createElement('video')
      video.srcObject = stream
      video.autoplay = true
      video.playsInline = true
      video.muted = true
      await video.play()
      videoRef.current = video

      setEnabled(true)

      // Detection loop
      let lastTime = -1
      const detect = () => {
        if (!videoRef.current || !detectorRef.current) return
        const now = performance.now()
        if (now === lastTime) {
          rafRef.current = requestAnimationFrame(detect)
          return
        }
        lastTime = now

        const results = detectorRef.current.detectForVideo(videoRef.current, now)
        const hands = results.landmarks || []

        if (hands.length === 0) {
          setState(prev => prev.active ? { ...INITIAL_STATE } : prev)
        } else {
          const newState: HandState = {
            active: true,
            leftCenter: null,
            rightCenter: null,
            handDistance: null,
            leftOpenness: 0,
            rightOpenness: 0,
            center: null,
          }

          // Sort hands by x to determine left/right
          const sorted = hands
            .map((lm: any, i: number) => ({
              landmarks: lm,
              handedness: results.handedness?.[i]?.[0]?.categoryName || 'Unknown',
            }))
            .sort((a: any, b: any) => a.landmarks[0].x - b.landmarks[0].x)

          if (sorted.length >= 1) {
            const h0 = sorted[0]
            const wrist0: [number, number] = [h0.landmarks[0].x, h0.landmarks[0].y]
            newState.leftCenter = wrist0
            newState.leftOpenness = calcOpenness(h0.landmarks)
            newState.center = wrist0
          }

          if (sorted.length >= 2) {
            const h1 = sorted[1]
            const wrist1: [number, number] = [h1.landmarks[0].x, h1.landmarks[0].y]
            newState.rightCenter = wrist1
            newState.rightOpenness = calcOpenness(h1.landmarks)

            newState.handDistance = distance2D(newState.leftCenter!, wrist1)
            newState.center = [
              (newState.leftCenter![0] + wrist1[0]) / 2,
              (newState.leftCenter![1] + wrist1[1]) / 2,
            ]
          }

          setState(newState)
        }

        rafRef.current = requestAnimationFrame(detect)
      }
      rafRef.current = requestAnimationFrame(detect)

    } catch (err) {
      console.error('Hand tracking init failed:', err)
      setEnabled(false)
    }
  }, [])

  const stop = useCallback(() => {
    cancelAnimationFrame(rafRef.current)
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(t => t.stop())
      streamRef.current = null
    }
    if (detectorRef.current) {
      detectorRef.current.close()
      detectorRef.current = null
    }
    videoRef.current = null
    setEnabled(false)
    setState(INITIAL_STATE)
  }, [])

  const toggle = useCallback(() => {
    if (enabled) stop()
    else start()
  }, [enabled, start, stop])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      cancelAnimationFrame(rafRef.current)
      if (streamRef.current) {
        streamRef.current.getTracks().forEach(t => t.stop())
      }
    }
  }, [])

  return { enabled, state, toggle, start, stop }
}
