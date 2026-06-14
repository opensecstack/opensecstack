import { forwardRef } from "react";

interface ScrollSentinelProps {
  isFetchingNextPage: boolean;
  hasNextPage: boolean;
}

const ScrollSentinel = forwardRef<HTMLDivElement, ScrollSentinelProps>(
  function ScrollSentinel({ isFetchingNextPage, hasNextPage }, ref) {
    return (
      <div ref={ref} className="flex justify-center py-6">
        {isFetchingNextPage && (
          <div className="w-6 h-6 border-4 border-brand/20 border-t-brand rounded-full animate-spin" />
        )}
        {!hasNextPage && !isFetchingNextPage && null}
      </div>
    );
  }
);

export default ScrollSentinel;
