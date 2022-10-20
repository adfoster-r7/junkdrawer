require "readline"

def readline_completion
  proc do |s|
    ["hello", "world"]
  end
end

def main
  Readline.completion_proc = readline_completion
  Readline.basic_word_break_characters = ' '

  while input = Readline.readline("msf6 > ", true)
    return if input == "exit"

    puts input
  end
end

main
