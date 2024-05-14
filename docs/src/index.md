---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Tacowrap"
  text: "FUSE-based encrypted filesystem"
  tagline: My great project tagline
  image:
    src: /logo.svg
    alt: Tacowrap
  actions:
    - theme: brand
      text: Markdown Examples
      link: /examples/markdown-examples
    - theme: alt
      text: API Examples
      link: /examples/api-examples

features:
  - icon: 🐹
    title: Feature A
    details: Lorem ipsum dolor sit amet, consectetur adipiscing elit
  - icon: 🛡️
    title: Feature B
    details: Lorem ipsum dolor sit amet, consectetur adipiscing elit
  - icon: 😋
    title: Delicious naming
    details: Named after food, joining projects like <em>Bun</em> and <em>OpenTofu</em>.
---
<style>
:root {
  --vp-home-hero-name-color: transparent;
  --vp-home-hero-name-background: -webkit-linear-gradient(120deg, hwb(160 10% 10%) 30%, hwb(140 10% 10%));

  --vp-home-hero-image-background-image: linear-gradient(-45deg, hwb(160 10% 10%) 30%, hwb(140 10% 10%) 70%);
  --vp-home-hero-image-filter: blur(44px);
}

@media (min-width: 640px) {
  :root {
    --vp-home-hero-image-filter: blur(56px);
  }
}

@media (min-width: 960px) {
  :root {
    --vp-home-hero-image-filter: blur(68px);
  }
}
</style>
