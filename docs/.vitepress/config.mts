import { defineConfig } from "vitepress";
import { generateSidebar } from "vitepress-sidebar";

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "Tacowrap",
  description: "FUSE-based encrypted filesystem",
  appearance: "dark",
  lastUpdated: true,
  srcDir: "src",
  base: "/tacowrap/",
  markdown: {
    theme: {
      dark: "one-dark-pro",
      light: "min-light",
    },
    lineNumbers: true,
    image: {
      lazyLoading: true,
    },
  },
  vite: {
    resolve: {
      preserveSymlinks: true,
    },
  },
  head: [
    ["link", { rel: "icon", type: "image/svg+xml", href: "/tacowrap/logo.svg" }],
    ["meta", { name: "color-scheme", content: "dark light" }],
    ["meta", { name: "theme-color", content: "#00d948" }],
    ["meta", { name: "og:type", content: "website" }],
    ["meta", { name: "og:locale", content: "en" }],
    ["meta", { name: "og:site_name", content: "Tacowrap" }],
  ],
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    logo: { src: "/logo.svg", width: 24, height: 24 },
    editLink: {
      pattern: "https://github.com/dnaka91/tacowrap/edit/main/docs/src/:path",
      text: "Edit this page on GitHub",
    },
    nav: [
      { text: "Home", link: "/" },
      { text: "Examples", link: "/markdown-examples" },
    ],

    sidebar: generateSidebar({
      capitalizeFirst: true,
      documentRootPath: "src",
      sortMenusByName: true,

      useFolderTitleFromIndexFile: true,
      useTitleFromFileHeading: true,
      useTitleFromFrontmatter: true,
    }),

    outline: "deep",

    socialLinks: [{ icon: "github", link: "https://github.com/dnaka91/tacowrap" }],

    footer: {
      message: "Released under the MIT License.",
      copyright: "Copyright © 2024-present Dominik Nakamura",
    },

    search: {
      provider: "local",
    },

    externalLinkIcon: true,
  },
});
