<?php
namespace AtlasFixture;

interface Greeter {
    public function greet(string $name): string;
}

trait Named {
    public function label(): string { return 'test fixture'; }
}

class Greeting implements Greeter {
    use Named;
    public const PREFIX = 'Hello';

    public function __construct(private string $prefix = self::PREFIX) {}

    public function greet(string $name): string {
        return $this->prefix . ', ' . $name;
    }
}

function dangerous_example($input) {
    eval($input);
    shell_exec($input);
    unserialize($input);
}
