i have what i think is a cool new direction for my project, hellas. hellas is protocol for trustlessly delegating arbitrary tensor compute to an anonymized peer-to-peer network, arbitrated by currency.

so i've been a huge fan of nix, the package manager and its whole philosophy for ages- i consider it to solve software packaging

but one of my more recent insights is actually that it solves a specific problem regarding software that is a lot more generalisable

nix works on the principle of input addressing:

each package in nix is described symbolically as a derivation- a self-describing function that declares:

 - inputs- what  passed to it at evaluation-time (eg, `gcc`, `my_file.c`)
 - transformation- the operations to perform (eg, `gcc my_file.c -o $out`)

optional: a symbol representing the pre-shared semantics of how to run those operations (eg, `aarch64-darwin`)
there's some other stuff too, metadata, signatures etc. but we can ignore that here for now. together,
these functions can be composed as a DAG and evaluated to produce a result.

haters will say:
  nothing new there- lots of software i use works like that- npm, pypi, debian etc.
  i have a uv lockfile that formally specifies the DAG that i want to run, how is nix different?

its true that pypi can model packages as DAGs, but they are content-addressed (CDNs love it!)
in the uv lockfile, the hash you see is the hash of the contents package:

  id = hash ( self.transformation(inputs) )

note the brackets on `self.transformation(inputs)`- we must _run_ the function to know its identifier,
and thus we cannot represent things that haven't happened yet.

nix introduces an additional layer of indirection: derivations (and thus packages) have a canonical identifier:

  id = hash ( self.transformation, [hash(input.id) for input in self.inputs] )

what's crucial here is the brackets are gone- simply the hash a representation of the function itself and the hashes of its inputs to find its identifier



now you can know the identifier of a derivation _before_ it's evaluated- we can describe
transformations that haven't happened yet and their inputs, which also may or may not have happened yet.

why is this useful? it allows lazy evaluation- we have a symbol that we can use in-place of the result itself- we can compose it in a structured way without knowing any of the concrete values.

why is this actually useful? caching, mostly. if you know the identifier of a derivation, you can look it up in the cache and avoid recomputing it.


when we want to turn that symbol into a concrete value, we simply evaluate the derivation.



if a derivation has no inputs, it's identifier simply becomes:

  id = hash ( self.transformation() )

the result- thus such 'leaf' nodes are content-addressed.

this property, laziness,

if a nix derivation has zero inputs, we can
how the concrete binaries from its own `input` derivations. , concrete artefacts from its inputs-

each 'input' to the derivation is either itself a derivation, or a content-addressed artefact such as a compiled binary or a configuration file.

the fact that the derivation

in a completely determinate world, if i told you my starting point and how i moved, you could know my exact location,
