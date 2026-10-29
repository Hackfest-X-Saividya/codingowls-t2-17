// The eight-point star used as the logo mark and as a section accent
export default function BrandStar({ className = "w-5 h-5" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 1L13.76 7.75L19.78 4.22L16.25 10.24L23 12L16.25 13.76L19.78 19.78L13.76 16.25L12 23L10.24 16.25L4.22 19.78L7.75 13.76L1 12L7.75 10.24L4.22 4.22L10.24 7.75Z" />
    </svg>
  );
}
