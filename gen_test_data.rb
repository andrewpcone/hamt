#!/usr/bin/env ruby

File.open("test_data", 'w') do |f|
  100_000_000.times do
    if rand < 0.9
      f.puts ["S", rand(1_000_000).to_s(36), rand(1_000_000).to_s(36)].join("\t")
    else
      f.puts ["D", rand(1_000_000).to_s(36)].join("\t")
    end
  end
end
