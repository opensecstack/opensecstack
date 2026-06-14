import { useEffect } from "react";

interface SEOProps {
  title?: string;
  description?: string;
  image?: string;
  url?: string;
  type?: string;
  rssHref?: string;
  rssTitle?: string;
}

function setMeta(name: string, content: string, attr = "name") {
  let el = document.querySelector(`meta[${attr}="${name}"]`);
  if (!el) {
    el = document.createElement("meta");
    el.setAttribute(attr, name);
    document.head.appendChild(el);
  }
  el.setAttribute("content", content);
}

function removeMeta(name: string, attr = "name") {
  document.querySelector(`meta[${attr}="${name}"]`)?.remove();
}

export default function SEO({
  title,
  description,
  image,
  url,
  type = "website",
  rssHref,
  rssTitle,
}: SEOProps) {
  useEffect(() => {
    const siteTitle = "SIN";
    const fullTitle = title ? `${title} — ${siteTitle}` : siteTitle;

    document.title = fullTitle;

    if (description) {
      setMeta("description", description);
      setMeta("og:description", description.slice(0, 200), "property");
      setMeta("twitter:description", description.slice(0, 200));
    } else {
      removeMeta("description");
    }

    setMeta("og:title", fullTitle, "property");
    setMeta("og:type", type, "property");
    setMeta("og:site_name", "SIN", "property");

    if (image) {
      setMeta("og:image", image, "property");
      setMeta("twitter:image", image);
      setMeta("twitter:card", "summary_large_image");
    } else {
      setMeta("twitter:card", "summary");
    }

    if (url) {
      setMeta("og:url", url, "property");
    }

    if (rssHref) {
      let link = document.querySelector(
        `link[rel="alternate"][type="application/rss+xml"]`
      ) as HTMLLinkElement | null;
      if (!link) {
        link = document.createElement("link");
        link.setAttribute("rel", "alternate");
        link.setAttribute("type", "application/rss+xml");
        document.head.appendChild(link);
      }
      link.setAttribute("href", rssHref);
      link.setAttribute("title", rssTitle ?? "SIN RSS");
    }

    return () => {
      if (rssHref) {
        document
          .querySelector(`link[rel="alternate"][type="application/rss+xml"]`)
          ?.remove();
      }
    };
  }, [title, description, image, url, type, rssHref, rssTitle]);

  return null;
}
