<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Tests;

use FilesystemIterator;
use LogicException;
use Obresoft\Racoony\CodeScanner\ASTFileScannerFactory;
use Obresoft\Racoony\Config\ApplicationData;
use Obresoft\Racoony\Insight\Insight;
use Obresoft\Racoony\ScanRunner;
use Obresoft\Racoony\Tests\Attributes\TestsRule;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionClass;
use SplFileInfo;

use function count;
use function file_get_contents;
use function is_dir;
use function is_string;
use function sort;
use function sprintf;
use function str_contains;
use function str_ends_with;

use const DIRECTORY_SEPARATOR;

/**
 * @internal
 */
abstract class AbstractTestCase extends TestCase
{
    /** @var array<string,string>|null Cached content of Laravel fixtures: [absolutePath => content] */
    private static ?array $cachedLaravelFixtureContentsByPath = null;

    /** @var list<string>|null Cached list of Laravel fixture file paths */
    private static ?array $cachedLaravelFixturePaths = null;

    final public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (null === self::$cachedLaravelFixtureContentsByPath || null === self::$cachedLaravelFixturePaths) {
            self::initializeLaravelFixturesCache();
        }
    }

    /**
     * @param list<Insight> $expected
     * @throws Exception
     */
    final public function runTest(
        string $sourceCode,
        array $expected,
        string $fileAbsolutePath = '',
        ?ApplicationData $applicationData = null,
    ): void {
        $fakeFilesByPath = [$fileAbsolutePath => $sourceCode];
        $fileInfoListForRunner = [$this->createFileInfoMock($fileAbsolutePath)];

        if ($this instanceof LaravelRule) {
            foreach (self::$cachedLaravelFixtureContentsByPath as $fixturePath => $fixtureContent) {
                $fakeFilesByPath[$fixturePath] = $fixtureContent;
            }

            foreach (self::$cachedLaravelFixturePaths as $fixturePath) {
                $fileInfoListForRunner[] = $this->createFileInfoMock($fixturePath);
            }
        }

        $sourceCodeProvider = new FileReaderFake($fakeFilesByPath);
        $scanner = ASTFileScannerFactory::create($sourceCodeProvider, $applicationData);

        $rules = [$this->getTestedRuleClass()];
        $vulnerabilities = (new ScanRunner($fileInfoListForRunner, $scanner, $rules))->run();

        $actualVulnerabilities = array_values(array_filter(
            $vulnerabilities,
            static fn (Insight $v) => $v->getFile() === $fileAbsolutePath,
        ));

        $this->assertVulnerabilitiesEqual($expected, $actualVulnerabilities, $sourceCode);
    }

    protected function vulnerabilitiesAreEqual(Insight $a, Insight $b): bool
    {
        return $a->getFile() === $b->getFile()
            && $a->getType() === $b->getType()
            && $a->getMessage() === $b->getMessage()
            && $a->getLine() === $b->getLine()
            && $a->getSeverity() === $b->getSeverity();
    }

    /**
     * @param list<Insight> $expected
     * @param list<Insight> $actual
     */
    protected function assertVulnerabilitiesEqual(array $expected, array $actual, string $codeContext = ''): void
    {
        self::assertCount(
            count($expected),
            $actual,
            sprintf("Expected %d vulnerabilities, got %d for code:\n%s", count($expected), count($actual), $codeContext),
        );

        foreach ($expected as $i => $expectedVulnerability) {
            self::assertTrue(
                $this->vulnerabilitiesAreEqual($expectedVulnerability, $actual[$i]),
                sprintf(
                    "Vulnerability mismatch at index %d for code:\n%s\nExpected:\n%s\nGot:\n%s",
                    $i,
                    $codeContext,
                    print_r($expectedVulnerability, true),
                    print_r($actual[$i], true),
                ),
            );
        }
    }

    private static function initializeLaravelFixturesCache(): void
    {
        $fixtureRoots = [
            __DIR__ . '/Stubs/laravel',
        ];

        $paths = [];
        foreach ($fixtureRoots as $root) {
            if (!is_dir($root)) {
                continue;
            }
            foreach (self::collectPhpFilesRecursively($root) as $path) {
                $paths[] = $path;
            }
        }

        sort($paths);

        $contents = [];
        foreach ($paths as $path) {
            $content = file_get_contents($path);
            if (is_string($content)) {
                $contents[$path] = $content;
            }
        }

        self::$cachedLaravelFixturePaths = $paths;
        self::$cachedLaravelFixtureContentsByPath = $contents;
    }

    private function getTestedRuleClass(): string
    {
        $reflection = new ReflectionClass($this);
        $attributes = $reflection->getAttributes(TestsRule::class);

        if ([] === $attributes) {
            throw new LogicException('Missing #[TestsRule(...)] attribute on test class.');
        }

        return $attributes[0]->newInstance()->ruleClass;
    }

    /**
     * Recursively collect all PHP files under the given directory.
     *
     * @return list<string>
     */
    private static function collectPhpFilesRecursively(string $directory): array
    {
        $paths = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $info */
        foreach ($iterator as $info) {
            if (!$info->isFile()) {
                continue;
            }
            $path = $info->getPathname();

            if (str_contains($path, DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR)) {
                continue;
            }

            if (str_ends_with($path, '.php')) {
                $paths[] = $path;
            }
        }

        return $paths;
    }

    private function createFileInfoMock(string $absolutePath): SplFileInfo
    {
        $fileMock = $this->createMock(SplFileInfo::class);
        $fileMock->method('getRealPath')->willReturn($absolutePath);

        return $fileMock;
    }
}
