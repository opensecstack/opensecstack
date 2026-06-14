export default function Logo({ size = 24 }: { size?: number }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 32 32"
      aria-hidden="true"
    >
      <path
        d="M16 2L29 7.5V16C29 23.5 23 28.5 16 31C9 28.5 3 23.5 3 16V7.5Z"
        fill="#6366f1"
      />
      <text
        x="16"
        y="22"
        fontFamily="system-ui,-apple-system,sans-serif"
        fontWeight="800"
        fontSize="11"
        fill="white"
        textAnchor="middle"
      >
        SIN
      </text>
    </svg>
  );
}
