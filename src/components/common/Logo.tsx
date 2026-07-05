// HashBrown 브랜드 엠블럼 — 포렌식 모티프: 돋보기로 들여다보는 지문(digital forensics).
interface LogoProps {
  size?: number;
  className?: string;
}

let _gid = 0;

export function BrandLogo({ size = 32, className }: LogoProps) {
  // 동일 페이지 내 다중 인스턴스 시 id 충돌 방지
  const id = `hb-grad-${(_gid += 1)}`;
  const clip = `hb-clip-${_gid}`;

  return (
    <svg width={size} height={size} viewBox="0 0 48 48" fill="none" className={className} aria-label="HashBrown">
      <defs>
        <linearGradient id={id} x1="7" y1="4" x2="41" y2="44" gradientUnits="userSpaceOnUse">
          <stop stopColor="#8b5cf6" />
          <stop offset="0.55" stopColor="#6d28d9" />
          <stop offset="1" stopColor="#4c1d95" />
        </linearGradient>
        <clipPath id={clip}>
          <circle cx="21" cy="21" r="7.3" />
        </clipPath>
      </defs>

      {/* 라운드 헥사곤 배지 */}
      <path
        d="M21 3.9a6 6 0 0 1 6 0l12.99 7.5a6 6 0 0 1 3 5.2v14.8a6 6 0 0 1-3 5.2L27 44.1a6 6 0 0 1-6 0l-12.99-7.5a6 6 0 0 1-3-5.2V16.6a6 6 0 0 1 3-5.2Z"
        fill={`url(#${id})`}
      />

      {/* 지문 능선 (돋보기 렌즈 안으로 클리핑) */}
      <g
        clipPath={`url(#${clip})`}
        fill="none"
        stroke="#ffffff"
        strokeWidth="1.2"
        strokeLinecap="round"
      >
        <path d="M15.4 23.7 A6 6 0 1 1 26.6 23.7" strokeOpacity="0.92" />
        <path d="M17 24.1 A4.4 4.4 0 1 1 25 24.1" strokeOpacity="0.85" />
        <path d="M18.6 24.4 A2.9 2.9 0 1 1 23.4 24.4" strokeOpacity="0.8" />
        <path d="M19.9 21.9 Q21 20.5 22.1 21.9" strokeOpacity="0.95" />
      </g>

      {/* 돋보기 렌즈 + 손잡이 */}
      <circle cx="21" cy="21" r="8.5" stroke="#ffffff" strokeWidth="2.2" fill="none" />
      <path d="M27.4 27.4 L34.8 34.8" stroke="#ffffff" strokeWidth="2.8" strokeLinecap="round" />
    </svg>
  );
}
