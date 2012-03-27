# Grack

This particular grack fork adds **TODO**.

## Setup

1. Create a temp folder for your git repositories, `/tmp/git-repos` for example.
2. Edit `config.ru`
  - change `project_root` to your git repository folder (`/tmp/git-repos`).
  - change `git_path` to the full path to your git binary. Use `which git`.
3. Start server using `rackup config.ru`.
4. Navigate to your temp git repository folder and clone an existing project `git clone --bare https://oleander@github.com/Tarrasch/room-booker-rb.git`.
5. You can now clone the project using Grack. `git clone http://localhost:9292/room-booker-rb.git`

