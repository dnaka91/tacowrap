# Changelog

All notable changes to this project will be documented in this file.

<!-- markdownlint-disable no-duplicate-header -->
<!-- markdownlint-disable no-trailing-spaces -->

## Unreleased

### ⛰️ Features

- _fuse_: Handle open/flush/release calls ([3cbf58d](https://github.com/dnaka91/tacowrap/commit/3cbf58d7c394df3c339913e91859e09d9dfda784))
  > Properly handle open calls before read operations as well as flush and
  > release calls that happen once the read is finished.
  > 
  > This includes to keep file handles around, which are currently not
  > utilized in any special way but give some assurance that the underlying
  > file actually exists.
- _fuse_: Handle setattr/mkdir/rmdir calls ([9a7220f](https://github.com/dnaka91/tacowrap/commit/9a7220fbacc8bf4ead77bb456aed7b778989d674))
  > First steps of write support by creating and removing directories as
  > well as changing attributes of both files and directories.
- _fuse_: Handle rename calls ([ca1e163](https://github.com/dnaka91/tacowrap/commit/ca1e1639af260b1a3d4cae21d67eab4231b281d6))
  > Allows to rename directories and files, which is usually immediately
  > followed after creating a new directory through a GUI file manager.
- _fuse_: Handle unlink/write/create calls ([b09b349](https://github.com/dnaka91/tacowrap/commit/b09b34982723a5ba9b11a34f9ebbada20439647c))
- Show detailed error when decryption fails ([1334c47](https://github.com/dnaka91/tacowrap/commit/1334c47051848f683555a4f431347ac6a49d1267))
  > It's hard to tell what file/folder name is invalid with the current
  > errors, so the errors are now more extensive in this case and mentioned
  > the name that cause a decryption failure.
- Include timestamp in logs ([e481f94](https://github.com/dnaka91/tacowrap/commit/e481f9418d366701d93ef615e9d5c7bb83e78b0a))
  > To better debug the behavior in currently not fully implemented parts of
  > the FUSE interface, logs now include a timestamp at the start.

### 🐛 Bug Fixes

- Correctly calculate file size after write ([4f6e3f3](https://github.com/dnaka91/tacowrap/commit/4f6e3f3f36e612cc410169011dab17d0726a2a77))
  > The file header was not been taken into account when calculating the new
  > size of a file after writing to it.

### 📚 Documentation

- Add changelog to the project ([986598b](https://github.com/dnaka91/tacowrap/commit/986598b3f27cc827b765925d14ee54ef7f1d3c50))

### 🚜 Refactor

- Split up fuse code into multiple modules ([80076bd](https://github.com/dnaka91/tacowrap/commit/80076bd3635ad3f8ce68da3988e4cf319ee73dd6))
  > The implementation of the FUSE interface became exceedingly large and
  > splitting it up into smaller modules helps coping with the amount of
  > logic.

### 🧪 Testing

- Correct broken config test ([897a495](https://github.com/dnaka91/tacowrap/commit/897a495fc1ddc314c5c3f0208d50a205f7eeb190))
  > After adding in validation the test didn't work anymore as many
  > parameters were below the minimum limit and some feature flags collided.

### ⚙️ Miscellaneous Tasks

- Initial commit ([2adf571](https://github.com/dnaka91/tacowrap/commit/2adf571580ed4486c76623e9239131ce19cf16c7))

<!-- generated by git-cliff -->
